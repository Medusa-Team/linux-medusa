// SPDX-License-Identifier: GPL-2.0-only

#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/poll.h>
#include <linux/rcupdate.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/unaligned.h>
#include <linux/uaccess.h>
#include <uapi/linux/medusa.h>

#include "l3/arch.h"
#include "l3/decision_cache.h"
#include "l3/health.h"
#include "l3/kobject.h"
#include "l3/med_cache.h"
#include "l3/med_model.h"
#include "l3/pending.h"
#include "l3/protocol_stats.h"
#include "l3/registry.h"
#include "l3/server.h"
#include "l4/auth_server.h"
#include "l4/transport.h"

#define MODULENAME "miscdevice/v4"
#define MEDUSA_MISC_MINOR 111

struct medusa_v4_frame {
	struct list_head node;
	size_t length;
	size_t capacity;
	u8 data[];
};

struct medusa_v4_class {
	struct list_head node;
	struct medusa_kclass_s *class;
	u32 id;
};

struct medusa_v4_event {
	struct list_head node;
	struct medusa_evtype_s *event;
	u32 id;
	bool policy_staged;
};

struct medusa_v4_session {
	struct mutex state_lock;
	struct mutex read_lock;
	struct mutex write_lock;
	spinlock_t queue_lock;
	wait_queue_head_t read_wait;
	struct list_head frames;
	struct list_head classes;
	struct list_head events;
	struct pid *owner_tgid;
	enum medusa_protocol_state state;
	u64 enabled_features;
	u64 expected_generation;
	u32 next_class_id;
	u32 next_event_id;
	bool connected;
	bool replacing_policy;
};

static struct medusa_v4_session v4_session;
static struct medusa_transport medusa_v4_transport;
static struct medusa_server_health constable_health =
	MEDUSA_SERVER_HEALTH_INIT;

static void medusa_v4_close_wake(void)
{
	wake_up_all(&v4_session.read_wait);
}

static bool medusa_v4_is_healthy(void)
{
	return medusa_server_health_is_healthy(&constable_health);
}

static enum medusa_health_reason medusa_v4_health_reason(void)
{
	return medusa_server_health_reason(&constable_health);
}

static int medusa_v4_add_class(struct medusa_kclass_s *class);
static void medusa_v4_del_class(struct medusa_kclass_s *class);
static int medusa_v4_add_event(struct medusa_evtype_s *event);
static void medusa_v4_del_event(struct medusa_evtype_s *event);
static enum medusa_answer_t
medusa_v4_decide(struct medusa_event_s *event, struct medusa_kobject_s *subject,
		 struct medusa_kobject_s *object,
		 struct medusa_authserver_decision *decision);

static struct medusa_authserver_s medusa_v4_authserver = {
	.name = MODULENAME,
	.close = medusa_v4_close_wake,
	.add_kclass = medusa_v4_add_class,
	.del_kclass = medusa_v4_del_class,
	.add_evtype = medusa_v4_add_event,
	.del_evtype = medusa_v4_del_event,
	.decide = medusa_v4_decide,
	.is_healthy = medusa_v4_is_healthy,
	.health_reason = medusa_v4_health_reason,
};

static struct medusa_v4_frame *
medusa_v4_frame_new(u16 type, u64 request_id, u64 generation,
		    size_t payload_capacity)
{
	struct medusa_frame_header *header;
	struct medusa_v4_frame *frame;

	if (payload_capacity > MEDUSA_FRAME_MAX_PAYLOAD)
		return NULL;
	frame = kvzalloc(struct_size(frame, data,
				    MEDUSA_FRAME_HEADER_SIZE + payload_capacity),
			 GFP_KERNEL);
	if (!frame)
		return NULL;
	INIT_LIST_HEAD(&frame->node);
	frame->length = MEDUSA_FRAME_HEADER_SIZE;
	frame->capacity = MEDUSA_FRAME_HEADER_SIZE + payload_capacity;
	header = (struct medusa_frame_header *)frame->data;
	header->version = cpu_to_le16(MEDUSA_PROTOCOL_VERSION);
	header->type = cpu_to_le16(type);
	header->request_id = cpu_to_le64(request_id);
	header->policy_generation = cpu_to_le64(generation);
	return frame;
}

static int medusa_v4_frame_add(struct medusa_v4_frame *frame, u16 type,
			       u16 flags, const void *value, size_t value_length)
{
	struct medusa_frame_header *header;
	struct medusa_tlv *tlv;
	size_t length;
	size_t aligned;

	if (check_add_overflow((size_t)MEDUSA_TLV_HEADER_SIZE, value_length,
			       &length))
		return -EOVERFLOW;
	aligned = MEDUSA_TLV_ALIGN_UP(length);
	if (aligned < length || aligned > frame->capacity - frame->length)
		return -EMSGSIZE;
	tlv = (struct medusa_tlv *)(frame->data + frame->length);
	tlv->type = cpu_to_le16(type);
	tlv->flags = cpu_to_le16(flags);
	tlv->length = cpu_to_le32(length);
	if (value_length)
		memcpy((u8 *)tlv + MEDUSA_TLV_HEADER_SIZE, value, value_length);
	frame->length += aligned;
	header = (struct medusa_frame_header *)frame->data;
	header->payload_length =
		cpu_to_le32(frame->length - MEDUSA_FRAME_HEADER_SIZE);
	return 0;
}

static int medusa_v4_frame_add_u8(struct medusa_v4_frame *frame, u16 type,
				  u8 value)
{
	return medusa_v4_frame_add(frame, type, 0, &value, sizeof(value));
}

static int medusa_v4_frame_add_u16(struct medusa_v4_frame *frame, u16 type,
				   u16 value)
{
	__le16 wire = cpu_to_le16(value);

	return medusa_v4_frame_add(frame, type, 0, &wire, sizeof(wire));
}

static int medusa_v4_frame_add_u32(struct medusa_v4_frame *frame, u16 type,
				   u32 value)
{
	__le32 wire = cpu_to_le32(value);

	return medusa_v4_frame_add(frame, type, 0, &wire, sizeof(wire));
}

static int medusa_v4_frame_add_u64(struct medusa_v4_frame *frame, u16 type,
				   u64 value)
{
	__le64 wire = cpu_to_le64(value);

	return medusa_v4_frame_add(frame, type, 0, &wire, sizeof(wire));
}

static void medusa_v4_frame_free(struct medusa_v4_frame *frame)
{
	kvfree(frame);
}

static int medusa_v4_misc_queue(void *context, void *transport_frame)
{
	struct medusa_v4_session *session = context;
	struct medusa_v4_frame *frame = transport_frame;
	unsigned long flags;

	spin_lock_irqsave(&session->queue_lock, flags);
	if (!session->connected) {
		spin_unlock_irqrestore(&session->queue_lock, flags);
		medusa_v4_frame_free(frame);
		return -EPIPE;
	}
	list_add_tail(&frame->node, &session->frames);
	spin_unlock_irqrestore(&session->queue_lock, flags);
	wake_up_interruptible(&session->read_wait);
	return 0;
}

static struct medusa_transport medusa_v4_transport = {
	.name = "miscdevice",
	.context = &v4_session,
	.queue = medusa_v4_misc_queue,
};

static int medusa_v4_queue(struct medusa_v4_frame *frame)
{
	return medusa_transport_queue(&medusa_v4_transport, frame);
}

static void medusa_v4_purge_frames(void)
{
	struct medusa_v4_frame *frame;
	struct medusa_v4_frame *temporary;
	unsigned long flags;
	LIST_HEAD(discard);

	spin_lock_irqsave(&v4_session.queue_lock, flags);
	list_splice_init(&v4_session.frames, &discard);
	spin_unlock_irqrestore(&v4_session.queue_lock, flags);
	list_for_each_entry_safe(frame, temporary, &discard, node) {
		list_del(&frame->node);
		medusa_v4_frame_free(frame);
	}
}

static struct medusa_v4_class *
medusa_v4_find_class_locked(const struct medusa_kclass_s *class)
{
	struct medusa_v4_class *entry;

	list_for_each_entry(entry, &v4_session.classes, node)
		if (entry->class == class)
			return entry;
	return NULL;
}

static struct medusa_v4_class *medusa_v4_find_class_id_locked(u32 id)
{
	struct medusa_v4_class *entry;

	list_for_each_entry(entry, &v4_session.classes, node)
		if (entry->id == id)
			return entry;
	return NULL;
}

static struct medusa_v4_event *
medusa_v4_find_event_locked(const struct medusa_evtype_s *event)
{
	struct medusa_v4_event *entry;

	list_for_each_entry(entry, &v4_session.events, node)
		if (entry->event == event)
			return entry;
	return NULL;
}

static struct medusa_v4_event *medusa_v4_find_event_id_locked(u32 id)
{
	struct medusa_v4_event *entry;

	list_for_each_entry(entry, &v4_session.events, node)
		if (entry->id == id)
			return entry;
	return NULL;
}

static size_t medusa_v4_attribute_capacity(struct medusa_attribute_s *attrs)
{
	struct medusa_attribute_s *attr;
	size_t capacity = 0;

	for (attr = attrs; attr && attr->type != MED_END; attr++) {
		size_t name_length = strnlen(attr->name, MEDUSA_ATTRNAME_MAX);

		capacity += MEDUSA_TLV_ALIGN_UP(
			MEDUSA_TLV_HEADER_SIZE +
			sizeof(struct medusa_attribute_definition) + name_length);
	}
	return capacity;
}

static u16 medusa_v4_attr_flags(unsigned int type)
{
	u16 flags = 0;

	if (type & MED_RO)
		flags |= MEDUSA_ATTR_F_READ_ONLY;
	if (type & MED_KEY)
		flags |= MEDUSA_ATTR_F_PRIMARY_KEY;
	if ((type & 0x30U) == MED_BE)
		flags |= MEDUSA_ATTR_F_BIG_ENDIAN;
	if ((type & 0x30U) == MED_LE)
		flags |= MEDUSA_ATTR_F_LITTLE_ENDIAN;
	return flags;
}

static int medusa_v4_add_attributes(struct medusa_v4_frame *frame,
				    struct medusa_attribute_s *attrs)
{
	struct medusa_attribute_definition definition;
	struct medusa_attribute_s *attr;
	u8 *value;
	u32 id = 1;
	int error;

	for (attr = attrs; attr && attr->type != MED_END; attr++, id++) {
		size_t name_length = strnlen(attr->name, MEDUSA_ATTRNAME_MAX);
		size_t value_length = sizeof(definition) + name_length;

		if (attr->offset > U32_MAX || attr->length > U32_MAX ||
		    name_length > U16_MAX)
			return -EOVERFLOW;
		value = kzalloc(value_length, GFP_KERNEL);
		if (!value)
			return -ENOMEM;
		memset(&definition, 0, sizeof(definition));
		definition.id = cpu_to_le32(id);
		definition.offset = cpu_to_le32(attr->offset);
		definition.length = cpu_to_le32(attr->length);
		definition.type = cpu_to_le16(attr->type & 0x0fU);
		definition.flags = cpu_to_le16(medusa_v4_attr_flags(attr->type));
		definition.name_length = cpu_to_le16(name_length);
		memcpy(value, &definition, sizeof(definition));
		memcpy(value + sizeof(definition), attr->name, name_length);
		error = medusa_v4_frame_add(frame, MEDUSA_TLV_ATTRIBUTE,
					    MEDUSA_TLV_F_ARRAY, value,
					    value_length);
		kfree(value);
		if (error)
			return error;
	}
	return 0;
}

static struct medusa_v4_frame *
medusa_v4_class_definition_locked(struct medusa_v4_class *entry)
{
	struct medusa_v4_frame *frame;
	size_t name_length;
	size_t capacity;
	int error;

	name_length = strnlen(entry->class->name, MEDUSA_KCLASSNAME_MAX);
	capacity = 32 + MEDUSA_TLV_ALIGN_UP(MEDUSA_TLV_HEADER_SIZE +
					    name_length) +
		   medusa_v4_attribute_capacity(entry->class->attr);
	frame = medusa_v4_frame_new(MEDUSA_MSG_CLASS_DEFINITION, 0,
				    v4_session.expected_generation, capacity);
	if (!frame)
		return NULL;
	error = medusa_v4_frame_add_u32(frame, MEDUSA_TLV_CLASS_ID, entry->id);
	error = error ?: medusa_v4_frame_add(
		frame, MEDUSA_TLV_NAME, 0, entry->class->name, name_length);
	error = error ?: medusa_v4_frame_add_u32(
		frame, MEDUSA_TLV_OBJECT_SIZE, entry->class->kobject_size);
	error = error ?: medusa_v4_add_attributes(frame, entry->class->attr);
	if (error) {
		medusa_v4_frame_free(frame);
		return NULL;
	}
	return frame;
}

static struct medusa_v4_frame *
medusa_v4_event_definition_locked(struct medusa_v4_event *entry)
{
	struct medusa_v4_class *subject;
	struct medusa_v4_class *object;
	struct medusa_v4_frame *frame;
	struct medusa_evtype_s *event = entry->event;
	size_t name_length = strnlen(event->name, MEDUSA_EVNAME_MAX);
	size_t subject_name_length =
		strnlen(event->arg_name[0], MEDUSA_ATTRNAME_MAX);
	size_t object_name_length =
		strnlen(event->arg_name[1], MEDUSA_ATTRNAME_MAX);
	size_t capacity;
	int error;

	subject = medusa_v4_find_class_locked(event->arg_kclass[0]);
	object = medusa_v4_find_class_locked(event->arg_kclass[1]);
	if (!subject || !object)
		return NULL;
	capacity = 96 + MEDUSA_TLV_ALIGN_UP(MEDUSA_TLV_HEADER_SIZE +
					    name_length) +
		   MEDUSA_TLV_ALIGN_UP(MEDUSA_TLV_HEADER_SIZE +
				       subject_name_length) +
		   MEDUSA_TLV_ALIGN_UP(MEDUSA_TLV_HEADER_SIZE +
				       object_name_length) +
		   medusa_v4_attribute_capacity(event->attr);
	frame = medusa_v4_frame_new(MEDUSA_MSG_EVENT_DEFINITION, 0,
				    v4_session.expected_generation, capacity);
	if (!frame)
		return NULL;
	error = medusa_v4_frame_add_u32(frame, MEDUSA_TLV_EVENT_ID, entry->id);
	error = error ?: medusa_v4_frame_add(
		frame, MEDUSA_TLV_NAME, 0, event->name, name_length);
	error = error ?: medusa_v4_frame_add_u32(
		frame, MEDUSA_TLV_EVENT_SIZE, event->event_size);
	error = error ?: medusa_v4_frame_add_u32(
		frame, MEDUSA_TLV_SUBJECT_CLASS_ID, subject->id);
	error = error ?: medusa_v4_frame_add_u32(
		frame, MEDUSA_TLV_OBJECT_CLASS_ID, object->id);
	error = error ?: medusa_v4_frame_add(
		frame, MEDUSA_TLV_SUBJECT_NAME, 0, event->arg_name[0],
		subject_name_length);
	error = error ?: medusa_v4_frame_add(
		frame, MEDUSA_TLV_OBJECT_NAME, 0, event->arg_name[1],
		object_name_length);
	error = error ?: medusa_v4_frame_add_u16(
		frame, MEDUSA_TLV_TRIGGER, event->bitnr);
	error = error ?: medusa_v4_frame_add_u8(
		frame, MEDUSA_TLV_ENFORCEMENT, event->enforced);
	error = error ?: medusa_v4_add_attributes(frame, event->attr);
	if (error) {
		medusa_v4_frame_free(frame);
		return NULL;
	}
	return frame;
}

static int medusa_v4_add_class(struct medusa_kclass_s *class)
{
	struct medusa_v4_class *entry;
	struct medusa_v4_frame *frame = NULL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	mutex_lock(&v4_session.state_lock);
	if (medusa_v4_find_class_locked(class)) {
		mutex_unlock(&v4_session.state_lock);
		kfree(entry);
		return -EEXIST;
	}
	entry->class = class;
	entry->id = ++v4_session.next_class_id;
	list_add_tail(&entry->node, &v4_session.classes);
	if (v4_session.state == MEDUSA_STATE_DEFINITIONS ||
	    v4_session.state == MEDUSA_STATE_READY)
		frame = medusa_v4_class_definition_locked(entry);
	mutex_unlock(&v4_session.state_lock);
	if (frame)
		return medusa_v4_queue(frame);
	return 0;
}

static void medusa_v4_del_class(struct medusa_kclass_s *class)
{
	struct medusa_v4_class *entry = NULL;

	mutex_lock(&v4_session.state_lock);
	entry = medusa_v4_find_class_locked(class);
	if (entry)
		list_del(&entry->node);
	mutex_unlock(&v4_session.state_lock);
	kfree(entry);
}

static int medusa_v4_add_event(struct medusa_evtype_s *event)
{
	struct medusa_v4_event *entry;
	struct medusa_v4_frame *frame = NULL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	mutex_lock(&v4_session.state_lock);
	if (medusa_v4_find_event_locked(event)) {
		mutex_unlock(&v4_session.state_lock);
		kfree(entry);
		return -EEXIST;
	}
	entry->event = event;
	entry->id = ++v4_session.next_event_id;
	list_add_tail(&entry->node, &v4_session.events);
	if (v4_session.state == MEDUSA_STATE_DEFINITIONS ||
	    v4_session.state == MEDUSA_STATE_READY)
		frame = medusa_v4_event_definition_locked(entry);
	mutex_unlock(&v4_session.state_lock);
	if (frame)
		return medusa_v4_queue(frame);
	return 0;
}

static void medusa_v4_del_event(struct medusa_evtype_s *event)
{
	struct medusa_v4_event *entry = NULL;

	mutex_lock(&v4_session.state_lock);
	entry = medusa_v4_find_event_locked(event);
	if (entry)
		list_del(&entry->node);
	mutex_unlock(&v4_session.state_lock);
	kfree(entry);
}

static int medusa_v4_snapshot(struct medusa_attribute_s *attrs,
			      size_t object_size, const void *object, u8 **result)
{
	struct medusa_attribute_s *attr;
	u8 *snapshot;

	snapshot = kvzalloc(object_size, GFP_KERNEL);
	if (!snapshot)
		return -ENOMEM;
	for (attr = attrs; attr && attr->type != MED_END; attr++) {
		if (attr->offset > object_size ||
		    attr->length > object_size - attr->offset) {
			kvfree(snapshot);
			return -EOVERFLOW;
		}
		memcpy(snapshot + attr->offset, (const u8 *)object + attr->offset,
		       attr->length);
	}
	*result = snapshot;
	return 0;
}

static int medusa_v4_restore(struct medusa_attribute_s *attrs,
			     size_t object_size, const u8 *snapshot,
			     size_t snapshot_size, void **result)
{
	struct medusa_attribute_s *attr;
	u8 *object;

	if (snapshot_size != object_size)
		return -EMSGSIZE;
	object = kvzalloc(object_size, GFP_KERNEL);
	if (!object)
		return -ENOMEM;
	for (attr = attrs; attr && attr->type != MED_END; attr++) {
		if (attr->offset > object_size ||
		    attr->length > object_size - attr->offset) {
			kvfree(object);
			return -EOVERFLOW;
		}
		memcpy(object + attr->offset, snapshot + attr->offset,
		       attr->length);
	}
	*result = object;
	return 0;
}

static void medusa_v4_mark_degraded(enum medusa_health_reason reason)
{
	if (medusa_server_health_mark_unhealthy(&constable_health, reason))
		med_pr_warn("protocol v4 entered DEGRADED, reason=%d\n", reason);
	mutex_lock(&v4_session.state_lock);
	if (v4_session.connected)
		v4_session.state = MEDUSA_STATE_DEGRADED;
	mutex_unlock(&v4_session.state_lock);
	med_authserver_set_state(&medusa_v4_authserver,
				 MEDUSA_AUTHSERVER_DEGRADED);
	medusa_pending_request_cancel_all(MED_ERR);
	wake_up_all(&v4_session.read_wait);
}

static int medusa_v4_cache_unmonitor(
	struct medusa_kclass_s *class, struct medusa_kobject_s *object,
	const char *attribute_name, unsigned int bit)
{
	struct medusa_attribute_s *attribute;

	if (!class || !class->update)
		return -EOPNOTSUPP;
	for (attribute = class->attr;
	     attribute && attribute->type != MED_END; attribute++) {
		if (strcmp(attribute->name, attribute_name))
			continue;
		if (bit >= attribute->length * BITS_PER_BYTE)
			return -ERANGE;
		clear_bit(bit, (unsigned long *)(
			(u8 *)object + attribute->offset));
		return class->update(object) == MED_ALLOW ? 0 : -EIO;
	}
	return -ENOENT;
}

static void medusa_v4_apply_reply_cache_update(
	struct medusa_event_s *event, struct medusa_kclass_s *subject_class,
	struct medusa_kobject_s *subject, struct medusa_kclass_s *object_class,
	struct medusa_kobject_s *object, u8 cache_update)
{
	unsigned int bit = event->evtype_id->bitnr & MASK_BITNR;

	if (cache_update & MEDUSA_CACHE_UPDATE_SUBJECT)
		medusa_v4_cache_unmonitor(
			subject_class, subject, "med_sact", bit);
	if (cache_update & MEDUSA_CACHE_UPDATE_OBJECT)
		medusa_v4_cache_unmonitor(
			object_class, object, "med_oact", bit);
}

static enum medusa_answer_t
medusa_v4_decide(struct medusa_event_s *event, struct medusa_kobject_s *subject,
		 struct medusa_kobject_s *object,
		 struct medusa_authserver_decision *decision)
{
	struct medusa_pending_request pending;
	struct medusa_v4_class *subject_class;
	struct medusa_v4_class *object_class;
	struct medusa_v4_event *event_entry;
	struct medusa_v4_frame *frame = NULL;
	u8 *event_data = NULL;
	u8 *subject_data = NULL;
	u8 *object_data = NULL;
	enum medusa_answer_t answer = MED_ERR;
	u64 generation;
	int error;

	decision->request_id = 0;
	decision->policy_generation =
		(u64)READ_ONCE(medusa_authserver_magic);
	decision->unavailable = MEDUSA_AUTH_SERVER_UNREACHABLE;
	decision->request_present = false;
	decision->contacted = false;

	if (!in_task() || preempt_count() || irqs_disabled()) {
		decision->unavailable = MEDUSA_NON_SLEEPABLE_CONTEXT;
		return MED_ERR;
	}
	if (!medusa_v4_is_healthy())
		return MED_ERR;

	generation = (u64)READ_ONCE(medusa_authserver_magic);
	error = medusa_pending_request_register(&pending, generation);
	if (error) {
		if (error == -ENOSPC) {
			decision->unavailable = MEDUSA_AUTH_SERVER_OVERLOADED;
			medusa_v4_mark_degraded(MEDUSA_HEALTH_OVERLOADED);
		}
		return MED_ERR;
	}
	decision->request_id = pending.id;
	decision->policy_generation = generation;
	decision->request_present = true;

	mutex_lock(&v4_session.state_lock);
	event_entry = medusa_v4_find_event_locked(event->evtype_id);
	subject_class =
		medusa_v4_find_class_locked(event->evtype_id->arg_kclass[0]);
	object_class =
		medusa_v4_find_class_locked(event->evtype_id->arg_kclass[1]);
	if (!v4_session.connected ||
	    (v4_session.state != MEDUSA_STATE_READY &&
	     !(v4_session.replacing_policy &&
	       v4_session.state == MEDUSA_STATE_POLICY_INSTALL)) ||
	    !event_entry || !subject_class || !object_class) {
		error = -EPIPE;
		goto unlock;
	}
	error = medusa_v4_snapshot(event->evtype_id->attr,
				   event->evtype_id->event_size, event,
				   &event_data);
	error = error ?: medusa_v4_snapshot(
		subject_class->class->attr, subject_class->class->kobject_size,
		subject, &subject_data);
	if (object == subject) {
		object_data = subject_data;
	} else {
		error = error ?: medusa_v4_snapshot(
			object_class->class->attr,
			object_class->class->kobject_size, object,
			&object_data);
	}
	if (error)
		goto unlock;
	frame = medusa_v4_frame_new(
		MEDUSA_MSG_DECISION_REQUEST, pending.id, generation,
		96 + event->evtype_id->event_size +
		subject_class->class->kobject_size +
		object_class->class->kobject_size);
	if (!frame) {
		error = -ENOMEM;
		goto unlock;
	}
	error = medusa_v4_frame_add_u32(
		frame, MEDUSA_TLV_EVENT_ID, event_entry->id);
	error = error ?: medusa_v4_frame_add(
		frame, MEDUSA_TLV_EVENT_DATA, 0, event_data,
		event->evtype_id->event_size);
	error = error ?: medusa_v4_frame_add_u32(
		frame, MEDUSA_TLV_SUBJECT_CLASS_ID, subject_class->id);
	error = error ?: medusa_v4_frame_add(
		frame, MEDUSA_TLV_SUBJECT_DATA, 0, subject_data,
		subject_class->class->kobject_size);
	error = error ?: medusa_v4_frame_add_u32(
		frame, MEDUSA_TLV_OBJECT_CLASS_ID, object_class->id);
	error = error ?: medusa_v4_frame_add(
		frame, MEDUSA_TLV_OBJECT_DATA, 0, object_data,
		object_class->class->kobject_size);
unlock:
	mutex_unlock(&v4_session.state_lock);
	if (object_data != subject_data)
		kvfree(object_data);
	kvfree(subject_data);
	kvfree(event_data);
	if (error) {
		if (frame)
			medusa_v4_frame_free(frame);
		medusa_pending_request_unregister(&pending);
		return MED_ERR;
	}
	error = medusa_v4_queue(frame);
	if (error) {
		medusa_pending_request_unregister(&pending);
		return MED_ERR;
	}
	decision->contacted = true;
	error = medusa_pending_request_wait_timeout(
		&pending, msecs_to_jiffies(medusa_decision_timeout_ms()),
		&answer);
	if (error == -ETIMEDOUT) {
		decision->unavailable = MEDUSA_DECISION_TIMED_OUT;
		medusa_v4_mark_degraded(MEDUSA_HEALTH_DECISION_TIMEOUT);
	} else if (error == -ERESTARTSYS) {
		struct medusa_v4_frame *cancel;

		/*
		 * A delegated hook runs in the originating task.  Fatal-signal
		 * wakeup is therefore the task-exit cancellation point.
		 */
		cancel = medusa_v4_frame_new(
			MEDUSA_MSG_DECISION_CANCEL, pending.id, generation, 0);
		if (cancel)
			medusa_v4_queue(cancel);
	}
	if (!error && answer == MED_ALLOW && pending.cache_update)
		medusa_v4_apply_reply_cache_update(
			event, subject_class->class, subject,
			object_class->class, object,
			pending.cache_update);
	return answer;
}

static bool medusa_v4_tlv_known(u16 type)
{
	return (type >= MEDUSA_TLV_MIN_VERSION &&
		type <= MEDUSA_TLV_STATE) ||
	       (type >= MEDUSA_TLV_CLASS_ID &&
		type <= MEDUSA_TLV_ENFORCEMENT) ||
	       (type >= MEDUSA_TLV_FALLBACK_POLICY &&
		type <= MEDUSA_TLV_DOMAIN_RULE) ||
	       (type >= MEDUSA_TLV_ERROR_CODE &&
		type <= MEDUSA_TLV_OFFENDING_TYPE);
}

static int medusa_v4_validate_frame(const u8 *data, size_t count)
{
	const struct medusa_frame_header *header =
		(const struct medusa_frame_header *)data;
	size_t payload_length;
	size_t offset;

	if (count < MEDUSA_FRAME_HEADER_SIZE)
		return -EMSGSIZE;
	if (le16_to_cpu(header->version) != MEDUSA_PROTOCOL_VERSION)
		return -EPROTONOSUPPORT;
	if (le32_to_cpu(header->flags) & ~MEDUSA_FRAME_F_REQUIRED_MASK)
		return -EINVAL;
	if (header->reserved)
		return -EINVAL;
	payload_length = le32_to_cpu(header->payload_length);
	if (payload_length > MEDUSA_FRAME_MAX_PAYLOAD ||
	    payload_length != count - MEDUSA_FRAME_HEADER_SIZE)
		return -EMSGSIZE;
	offset = MEDUSA_FRAME_HEADER_SIZE;
	while (offset < count) {
		const struct medusa_tlv *tlv;
		size_t length;
		size_t aligned;
		size_t index;
		u16 type;
		u16 flags;

		if (count - offset < MEDUSA_TLV_HEADER_SIZE)
			return -EMSGSIZE;
		tlv = (const struct medusa_tlv *)(data + offset);
		length = le32_to_cpu(tlv->length);
		type = le16_to_cpu(tlv->type);
		flags = le16_to_cpu(tlv->flags);
		if (flags & ~(MEDUSA_TLV_F_REQUIRED | MEDUSA_TLV_F_ARRAY))
			return -EINVAL;
		if (length < MEDUSA_TLV_HEADER_SIZE)
			return -EMSGSIZE;
		aligned = MEDUSA_TLV_ALIGN_UP(length);
		if (aligned < length || aligned > count - offset)
			return -EMSGSIZE;
		if (!medusa_v4_tlv_known(type) &&
		    (flags & MEDUSA_TLV_F_REQUIRED))
			return -EOPNOTSUPP;
		for (index = length; index < aligned; index++)
			if (data[offset + index])
				return -EINVAL;
		offset += aligned;
	}
	return offset == count ? 0 : -EMSGSIZE;
}

static const void *medusa_v4_find_tlv(const u8 *data, size_t count, u16 type,
				      size_t *value_length, bool required)
{
	size_t offset = MEDUSA_FRAME_HEADER_SIZE;
	const void *found = NULL;

	while (offset < count) {
		const struct medusa_tlv *tlv =
			(const struct medusa_tlv *)(data + offset);
		size_t length = le32_to_cpu(tlv->length);

		if (le16_to_cpu(tlv->type) == type) {
			if (found)
				return ERR_PTR(-EEXIST);
			found = (const u8 *)tlv + MEDUSA_TLV_HEADER_SIZE;
			*value_length = length - MEDUSA_TLV_HEADER_SIZE;
		}
		offset += MEDUSA_TLV_ALIGN_UP(length);
	}
	if (!found && required)
		return ERR_PTR(-ENOENT);
	return found;
}

static int medusa_v4_get_u8(const u8 *data, size_t count, u16 type, u8 *value)
{
	size_t length = 0;
	const u8 *wire = medusa_v4_find_tlv(data, count, type, &length, true);

	if (IS_ERR(wire))
		return PTR_ERR(wire);
	if (length != sizeof(*wire))
		return -EMSGSIZE;
	*value = *wire;
	return 0;
}

static int medusa_v4_get_u16(const u8 *data, size_t count, u16 type,
			     u16 *value)
{
	size_t length = 0;
	const __le16 *wire =
		medusa_v4_find_tlv(data, count, type, &length, true);

	if (IS_ERR(wire))
		return PTR_ERR(wire);
	if (length != sizeof(*wire))
		return -EMSGSIZE;
	*value = get_unaligned_le16(wire);
	return 0;
}

static int medusa_v4_get_u32(const u8 *data, size_t count, u16 type,
			     u32 *value)
{
	size_t length = 0;
	const __le32 *wire =
		medusa_v4_find_tlv(data, count, type, &length, true);

	if (IS_ERR(wire))
		return PTR_ERR(wire);
	if (length != sizeof(*wire))
		return -EMSGSIZE;
	*value = get_unaligned_le32(wire);
	return 0;
}

static int medusa_v4_get_u64(const u8 *data, size_t count, u16 type,
			     u64 *value)
{
	size_t length = 0;
	const __le64 *wire =
		medusa_v4_find_tlv(data, count, type, &length, true);

	if (IS_ERR(wire))
		return PTR_ERR(wire);
	if (length != sizeof(*wire))
		return -EMSGSIZE;
	*value = get_unaligned_le64(wire);
	return 0;
}

static int medusa_v4_send_simple(u16 type, u64 request_id, u64 generation)
{
	struct medusa_v4_frame *frame =
		medusa_v4_frame_new(type, request_id, generation, 0);

	if (!frame)
		return -ENOMEM;
	return medusa_v4_queue(frame);
}

static int medusa_v4_handle_hello(const u8 *data, size_t count)
{
	const struct medusa_frame_header *header =
		(const struct medusa_frame_header *)data;
	struct medusa_v4_class *class;
	struct medusa_v4_event *event;
	struct medusa_v4_frame *frame;
	u64 required_features;
	u64 optional_features;
	u16 min_version;
	u16 max_version;
	int error;

	if (le64_to_cpu(header->request_id) ||
	    le64_to_cpu(header->policy_generation))
		return -EINVAL;
	error = medusa_v4_get_u16(
		data, count, MEDUSA_TLV_MIN_VERSION, &min_version);
	error = error ?: medusa_v4_get_u16(
		data, count, MEDUSA_TLV_MAX_VERSION, &max_version);
	error = error ?: medusa_v4_get_u64(
		data, count, MEDUSA_TLV_REQUIRED_FEATURES, &required_features);
	error = error ?: medusa_v4_get_u64(
		data, count, MEDUSA_TLV_OPTIONAL_FEATURES, &optional_features);
	if (error)
		return error;
	if (min_version > MEDUSA_PROTOCOL_VERSION ||
	    max_version < MEDUSA_PROTOCOL_VERSION)
		return -EPROTONOSUPPORT;
	if (required_features & ~MEDUSA_SUPPORTED_FEATURES)
		return -EOPNOTSUPP;
	v4_session.enabled_features =
		required_features | (optional_features & MEDUSA_SUPPORTED_FEATURES);
	v4_session.expected_generation =
		(u64)READ_ONCE(medusa_authserver_magic) + 1;
	v4_session.state = MEDUSA_STATE_DEFINITIONS;
	med_authserver_set_state(&medusa_v4_authserver,
				 MEDUSA_AUTHSERVER_DEFINITIONS);

	frame = medusa_v4_frame_new(
		MEDUSA_MSG_HELLO_ACK, 0, v4_session.expected_generation, 64);
	if (!frame)
		return -ENOMEM;
	error = medusa_v4_frame_add_u16(
		frame, MEDUSA_TLV_MIN_VERSION, MEDUSA_PROTOCOL_VERSION);
	error = error ?: medusa_v4_frame_add_u16(
		frame, MEDUSA_TLV_MAX_VERSION, MEDUSA_PROTOCOL_VERSION);
	error = error ?: medusa_v4_frame_add_u64(
		frame, MEDUSA_TLV_ENABLED_FEATURES, v4_session.enabled_features);
	error = error ?: medusa_v4_frame_add_u16(
		frame, MEDUSA_TLV_STATE, MEDUSA_STATE_DEFINITIONS);
	if (error) {
		medusa_v4_frame_free(frame);
		return error;
	}
	error = medusa_v4_queue(frame);
	if (error)
		return error;
	list_for_each_entry(class, &v4_session.classes, node) {
		frame = medusa_v4_class_definition_locked(class);
		if (!frame)
			return -ENOMEM;
		error = medusa_v4_queue(frame);
		if (error)
			return error;
	}
	list_for_each_entry(event, &v4_session.events, node) {
		frame = medusa_v4_event_definition_locked(event);
		if (!frame)
			return -ENOMEM;
		error = medusa_v4_queue(frame);
		if (error)
			return error;
	}
	return medusa_v4_send_simple(
		MEDUSA_MSG_DEFINITIONS_DONE, 0, v4_session.expected_generation);
}

static int medusa_v4_handle_policy_begin(const u8 *data, size_t count)
{
	const struct medusa_frame_header *header =
		(const struct medusa_frame_header *)data;
	struct medusa_v4_event *event;
	u64 generation = le64_to_cpu(header->policy_generation);
	bool replacement = v4_session.state == MEDUSA_STATE_READY;
	int error;

	if (count != MEDUSA_FRAME_HEADER_SIZE)
		return -EMSGSIZE;
	if (le64_to_cpu(header->request_id))
		return -ESTALE;
	if ((!replacement && generation != v4_session.expected_generation) ||
	    (replacement &&
	     generation != (u64)READ_ONCE(medusa_authserver_magic) + 1))
		return -ESTALE;
	if (replacement) {
		if (!(v4_session.enabled_features &
		      MEDUSA_FEATURE_ATOMIC_POLICY_REPLACE))
			return -EOPNOTSUPP;
		error = med_authserver_policy_replace_begin(
			&medusa_v4_authserver);
		if (error)
			return error;
		v4_session.expected_generation = generation;
		v4_session.replacing_policy = true;
	}
	error = medusa_decision_cache_begin(generation);
	if (error) {
		if (replacement) {
			med_authserver_policy_replace_abort(
				&medusa_v4_authserver);
			v4_session.replacing_policy = false;
			v4_session.expected_generation =
				(u64)READ_ONCE(medusa_authserver_magic);
		}
		return error;
	}
	list_for_each_entry(event, &v4_session.events, node)
		event->policy_staged = false;
	v4_session.state = MEDUSA_STATE_POLICY_INSTALL;
	if (!replacement)
		med_authserver_set_state(&medusa_v4_authserver,
					 MEDUSA_AUTHSERVER_POLICY_INSTALL);
	return 0;
}

static int medusa_v4_handle_policy_event(const u8 *data, size_t count)
{
	const struct medusa_frame_header *header =
		(const struct medusa_frame_header *)data;
	struct medusa_v4_event *event;
	struct medusa_domain_rule_spec *rules = NULL;
	u32 rule_count = 0;
	u32 rule_index = 0;
	u32 event_id;
	u8 policy;
	size_t offset;
	int error;

	if (le64_to_cpu(header->request_id) ||
	    le64_to_cpu(header->policy_generation) !=
		    v4_session.expected_generation)
		return -ESTALE;
	error = medusa_v4_get_u32(data, count, MEDUSA_TLV_EVENT_ID, &event_id);
	error = error ?: medusa_v4_get_u8(
		data, count, MEDUSA_TLV_FALLBACK_POLICY, &policy);
	if (error)
		return error;
	if (policy > MEDUSA_FALLBACK_ONLINE_REQUIRED)
		return -EINVAL;
	event = medusa_v4_find_event_id_locked(event_id);
	if (!event)
		return -ENOENT;
	if (event->policy_staged)
		return -EALREADY;
	error = med_authserver_stage_fallback_policy(
		&medusa_v4_authserver, event->event, policy);
	if (error)
		return error;

	offset = MEDUSA_FRAME_HEADER_SIZE;
	while (offset < count) {
		const struct medusa_tlv *tlv =
			(const struct medusa_tlv *)(data + offset);
		size_t length = le32_to_cpu(tlv->length);

		if (le16_to_cpu(tlv->type) == MEDUSA_TLV_DOMAIN_RULE)
			rule_count++;
		offset += MEDUSA_TLV_ALIGN_UP(length);
	}
	if (rule_count) {
		if (!(v4_session.enabled_features &
		      MEDUSA_FEATURE_DOMAIN_DECISION_CACHE))
			return -EOPNOTSUPP;
		rules = kcalloc(rule_count, sizeof(*rules), GFP_KERNEL);
		if (!rules)
			return -ENOMEM;
	}
	offset = MEDUSA_FRAME_HEADER_SIZE;
	while (offset < count) {
		const struct medusa_tlv *tlv =
			(const struct medusa_tlv *)(data + offset);
		size_t length = le32_to_cpu(tlv->length);

		if (le16_to_cpu(tlv->type) == MEDUSA_TLV_DOMAIN_RULE) {
			const struct medusa_domain_rule *rule =
				(const struct medusa_domain_rule *)
				((const u8 *)tlv + MEDUSA_TLV_HEADER_SIZE);
			size_t value_length =
				length - MEDUSA_TLV_HEADER_SIZE;

			if (value_length != sizeof(*rule) ||
			    memchr_inv(rule->reserved, 0,
				       sizeof(rule->reserved))) {
				error = -EINVAL;
				goto out;
			}
			rules[rule_index++] =
				(struct medusa_domain_rule_spec) {
					.subject_domain = le64_to_cpu(
						rule->subject_domain),
					.object_domain = le64_to_cpu(
						rule->object_domain),
					.selector = le64_to_cpu(
						rule->selector),
					.answer =
						(enum medusa_answer_t)
						rule->answer,
				};
		}
		offset += MEDUSA_TLV_ALIGN_UP(length);
	}
	error = medusa_decision_cache_stage_rules(
		event->event, rules, rule_count);
out:
	kfree(rules);
	if (error)
		return error;
	event->policy_staged = true;
	return 0;
}

static int medusa_v4_handle_policy_commit(const u8 *data, size_t count)
{
	const struct medusa_frame_header *header =
		(const struct medusa_frame_header *)data;
	struct medusa_v4_event *event;
	int error;

	if (count != MEDUSA_FRAME_HEADER_SIZE)
		return -EMSGSIZE;
	if (le64_to_cpu(header->request_id) ||
	    le64_to_cpu(header->policy_generation) !=
		    v4_session.expected_generation)
		return -ESTALE;
	list_for_each_entry(event, &v4_session.events, node)
		if (!event->policy_staged)
			return -ENODATA;
	error = medusa_decision_cache_prepare(
		v4_session.expected_generation);
	if (error)
		return error;
	/*
	 * Initial registration advances the registry to the prepared generation
	 * and exposes the server in one critical section. Publish the matching
	 * cache first: it remains invisible while its generation is still in the
	 * future, then becomes usable as soon as registration advances magic.
	 */
	if (!v4_session.replacing_policy)
		medusa_decision_cache_publish(v4_session.expected_generation);
	v4_session.state = MEDUSA_STATE_READY;
	medusa_server_health_mark_healthy(&constable_health);
	error = v4_session.replacing_policy ?
		med_authserver_policy_replace_commit(&medusa_v4_authserver) :
		med_register_authserver(&medusa_v4_authserver);
	if (error) {
		v4_session.state = MEDUSA_STATE_POLICY_INSTALL;
		medusa_server_health_mark_unhealthy(&constable_health,
						    MEDUSA_HEALTH_PROTOCOL_ERROR);
		medusa_decision_cache_abort();
		return error;
	}
	if ((u64)READ_ONCE(medusa_authserver_magic) !=
	    v4_session.expected_generation) {
		v4_session.state = MEDUSA_STATE_POLICY_INSTALL;
		medusa_server_health_mark_unhealthy(&constable_health,
						    MEDUSA_HEALTH_PROTOCOL_ERROR);
		med_unregister_authserver(&medusa_v4_authserver);
		medusa_decision_cache_abort();
		return -ESTALE;
	}
	if (v4_session.replacing_policy)
		medusa_decision_cache_publish(v4_session.expected_generation);
	if (v4_session.replacing_policy) {
		v4_session.replacing_policy = false;
		medusa_pending_request_cancel_all(MED_ERR);
	}
	set_auth_server_ready();
	return medusa_v4_send_simple(
		MEDUSA_MSG_POLICY_READY, 0, v4_session.expected_generation);
}

static int medusa_v4_handle_policy_abort(const u8 *data, size_t count)
{
	const struct medusa_frame_header *header =
		(const struct medusa_frame_header *)data;
	int error;

	if (count != MEDUSA_FRAME_HEADER_SIZE ||
	    le64_to_cpu(header->request_id))
		return -EMSGSIZE;
	if (!v4_session.replacing_policy ||
	    le64_to_cpu(header->policy_generation) !=
		    v4_session.expected_generation)
		return -ESTALE;
	error = med_authserver_policy_replace_abort(&medusa_v4_authserver);
	if (error)
		return error;
	medusa_decision_cache_abort();
	v4_session.expected_generation =
		(u64)READ_ONCE(medusa_authserver_magic);
	v4_session.replacing_policy = false;
	v4_session.state = MEDUSA_STATE_READY;
	return medusa_v4_send_simple(
		MEDUSA_MSG_POLICY_READY, 0, v4_session.expected_generation);
}

static int medusa_v4_handle_reply(const u8 *data, size_t count)
{
	const struct medusa_frame_header *header =
		(const struct medusa_frame_header *)data;
	u64 request_id = le64_to_cpu(header->request_id);
	u64 generation = le64_to_cpu(header->policy_generation);
	u16 wire_answer;
	s16 answer;
	u8 cache_update = MEDUSA_CACHE_UPDATE_NONE;
	size_t cache_length = 0;
	const u8 *cache_wire;
	int error;

	if (!request_id ||
	    (generation != v4_session.expected_generation &&
	     !(v4_session.replacing_policy &&
	       generation == (u64)READ_ONCE(medusa_authserver_magic))))
		return -ESTALE;
	error = medusa_v4_get_u16(data, count, MEDUSA_TLV_ANSWER, &wire_answer);
	if (error)
		return error;
	answer = (s16)wire_answer;
	if (answer != MED_ERR && answer != MED_DENY && answer != MED_ALLOW)
		return -EINVAL;
	cache_wire = medusa_v4_find_tlv(
		data, count, MEDUSA_TLV_CACHE_UPDATE, &cache_length, false);
	if (IS_ERR(cache_wire))
		return PTR_ERR(cache_wire);
	if (cache_wire) {
		if (!(v4_session.enabled_features &
		      MEDUSA_FEATURE_REPLY_CACHE_UPDATE))
			return -EOPNOTSUPP;
		if (cache_length != sizeof(*cache_wire))
			return -EMSGSIZE;
		cache_update = *cache_wire;
		if (cache_update > MEDUSA_CACHE_UPDATE_BOTH)
			return -EINVAL;
		if (cache_update != MEDUSA_CACHE_UPDATE_NONE &&
		    answer != MED_ALLOW)
			return -EINVAL;
	}
	error = medusa_pending_request_complete_with_cache(
		request_id, generation, answer, cache_update);
	if (!error)
		medusa_protocol_counter_inc(MEDUSA_PROTOCOL_REPLIES);
	return error;
}

static int medusa_v4_handle_progress(const u8 *data, size_t count)
{
	const struct medusa_frame_header *header =
		(const struct medusa_frame_header *)data;
	u64 request_id = le64_to_cpu(header->request_id);
	u64 generation = le64_to_cpu(header->policy_generation);
	int error;

	if (count != MEDUSA_FRAME_HEADER_SIZE)
		return -EMSGSIZE;
	if (!request_id ||
	    (generation != v4_session.expected_generation &&
	     !(v4_session.replacing_policy &&
	       generation == (u64)READ_ONCE(medusa_authserver_magic))))
		return -ESTALE;
	error = medusa_pending_request_renew(request_id, generation);
	if (!error)
		medusa_protocol_counter_inc(MEDUSA_PROTOCOL_LEASE_RENEWALS);
	return error;
}

static int medusa_v4_handle_object(const u8 *data, size_t count, bool update)
{
	const struct medusa_frame_header *header =
		(const struct medusa_frame_header *)data;
	struct medusa_v4_class *class;
	struct medusa_v4_frame *reply;
	struct medusa_kobject_s *fetched = NULL;
	void *key = NULL;
	const u8 *object_data;
	u8 *snapshot = NULL;
	size_t object_length = 0;
	u64 request_id = le64_to_cpu(header->request_id);
	u64 generation = le64_to_cpu(header->policy_generation);
	u32 class_id;
	s32 status = 0;
	__le32 wire_status;
	int error;

	if (!request_id ||
	    (generation != v4_session.expected_generation &&
	     !(v4_session.replacing_policy &&
	       generation == (u64)READ_ONCE(medusa_authserver_magic))))
		return -ESTALE;
	error = medusa_v4_get_u32(data, count, MEDUSA_TLV_CLASS_ID, &class_id);
	object_data = medusa_v4_find_tlv(
		data, count, MEDUSA_TLV_OBJECT_DATA, &object_length, true);
	if (IS_ERR(object_data))
		error = error ?: PTR_ERR(object_data);
	if (error)
		return error;
	class = medusa_v4_find_class_id_locked(class_id);
	if (!class)
		return -ENOENT;
	error = medusa_v4_restore(
		class->class->attr, class->class->kobject_size, object_data,
		object_length, &key);
	if (error)
		return error;
	if (update) {
		status = class->class->update ?
			class->class->update(key) : MED_ERR;
	} else {
		fetched = class->class->fetch ?
			class->class->fetch(key) : NULL;
		if (!fetched)
			status = -ENOENT;
		else
			error = medusa_v4_snapshot(
				class->class->attr, class->class->kobject_size,
				fetched, &snapshot);
	}
	if (error)
		goto out;
	reply = medusa_v4_frame_new(
		update ? MEDUSA_MSG_OBJECT_UPDATE_REPLY :
			 MEDUSA_MSG_OBJECT_FETCH_REPLY,
		request_id, generation,
		32 + (snapshot ? class->class->kobject_size : 0));
	if (!reply) {
		error = -ENOMEM;
		goto out;
	}
	wire_status = cpu_to_le32(status);
	error = medusa_v4_frame_add(
		reply, MEDUSA_TLV_STATUS, 0, &wire_status, sizeof(wire_status));
	if (!error && snapshot)
		error = medusa_v4_frame_add(
			reply, MEDUSA_TLV_OBJECT_DATA, 0, snapshot,
			class->class->kobject_size);
	if (error)
		medusa_v4_frame_free(reply);
	else
		error = medusa_v4_queue(reply);
out:
	/*
	 * Class fetch callbacks populate and return the caller-owned key
	 * object. They do not return a med_cache allocation.
	 */
	kvfree(key);
	kvfree(snapshot);
	return error;
}

static int medusa_v4_dispatch(const u8 *data, size_t count)
{
	const struct medusa_frame_header *header =
		(const struct medusa_frame_header *)data;
	u16 type = le16_to_cpu(header->type);

	switch (v4_session.state) {
	case MEDUSA_STATE_HANDSHAKE:
		return type == MEDUSA_MSG_HELLO ?
			medusa_v4_handle_hello(data, count) : -EPROTO;
	case MEDUSA_STATE_DEFINITIONS:
		return type == MEDUSA_MSG_POLICY_BEGIN ?
			medusa_v4_handle_policy_begin(data, count) : -EPROTO;
	case MEDUSA_STATE_POLICY_INSTALL:
		if (type == MEDUSA_MSG_POLICY_EVENT)
			return medusa_v4_handle_policy_event(data, count);
		if (type == MEDUSA_MSG_POLICY_COMMIT)
			return medusa_v4_handle_policy_commit(data, count);
		if (type == MEDUSA_MSG_POLICY_ABORT)
			return medusa_v4_handle_policy_abort(data, count);
		if (v4_session.replacing_policy &&
		    type == MEDUSA_MSG_DECISION_REPLY)
			return medusa_v4_handle_reply(data, count);
		if (v4_session.replacing_policy &&
		    type == MEDUSA_MSG_DECISION_PROGRESS)
			return medusa_v4_handle_progress(data, count);
		if (v4_session.replacing_policy &&
		    type == MEDUSA_MSG_OBJECT_FETCH)
			return medusa_v4_handle_object(data, count, false);
		if (v4_session.replacing_policy &&
		    type == MEDUSA_MSG_OBJECT_UPDATE)
			return medusa_v4_handle_object(data, count, true);
		return -EPROTO;
	case MEDUSA_STATE_READY:
		if (type == MEDUSA_MSG_POLICY_BEGIN)
			return medusa_v4_handle_policy_begin(data, count);
		if (type == MEDUSA_MSG_DECISION_REPLY)
			return medusa_v4_handle_reply(data, count);
		if (type == MEDUSA_MSG_DECISION_PROGRESS)
			return medusa_v4_handle_progress(data, count);
		if (type == MEDUSA_MSG_OBJECT_FETCH)
			return medusa_v4_handle_object(data, count, false);
		if (type == MEDUSA_MSG_OBJECT_UPDATE)
			return medusa_v4_handle_object(data, count, true);
		return -EPROTO;
	case MEDUSA_STATE_DEGRADED:
		return -ESHUTDOWN;
	default:
		return -ENOTCONN;
	}
}

static ssize_t medusa_v4_read(struct file *file, char __user *buffer,
			      size_t count, loff_t *position)
{
	struct medusa_v4_frame *frame;
	unsigned long flags;
	ssize_t result;
	int error;

	if (file->private_data != &v4_session)
		return -EBADF;
	if (*position)
		*position = 0;
	error = mutex_lock_interruptible(&v4_session.read_lock);
	if (error)
		return error;
	for (;;) {
		spin_lock_irqsave(&v4_session.queue_lock, flags);
		if (!list_empty(&v4_session.frames))
			break;
		if (!v4_session.connected) {
			spin_unlock_irqrestore(
				&v4_session.queue_lock, flags);
			result = -EPIPE;
			goto out_unlock;
		}
		spin_unlock_irqrestore(&v4_session.queue_lock, flags);
		if (file->f_flags & O_NONBLOCK) {
			result = -EAGAIN;
			goto out_unlock;
		}
		error = wait_event_interruptible(
			v4_session.read_wait,
			!READ_ONCE(v4_session.connected) ||
			!list_empty_careful(&v4_session.frames));
		if (error) {
			result = error;
			goto out_unlock;
		}
	}
	frame = list_first_entry(
		&v4_session.frames, struct medusa_v4_frame, node);
	if (count < frame->length) {
		spin_unlock_irqrestore(&v4_session.queue_lock, flags);
		result = -EMSGSIZE;
		goto out_unlock;
	}
	list_del(&frame->node);
	spin_unlock_irqrestore(&v4_session.queue_lock, flags);
	if (copy_to_user(buffer, frame->data, frame->length))
		result = -EFAULT;
	else
		result = frame->length;
	medusa_v4_frame_free(frame);
out_unlock:
	mutex_unlock(&v4_session.read_lock);
	return result;
}

static ssize_t medusa_v4_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *position)
{
	u8 *data;
	int error;

	if (file->private_data != &v4_session)
		return -EBADF;
	if (count > MEDUSA_FRAME_MAX_SIZE)
		return -EMSGSIZE;
	data = memdup_user(buffer, count);
	if (IS_ERR(data))
		return PTR_ERR(data);
	error = medusa_v4_validate_frame(data, count);
	if (error)
		goto out;
	error = mutex_lock_interruptible(&v4_session.write_lock);
	if (error)
		goto out;
	mutex_lock(&v4_session.state_lock);
	if (!v4_session.connected)
		error = -EPIPE;
	else
		error = medusa_v4_dispatch(data, count);
	mutex_unlock(&v4_session.state_lock);
	mutex_unlock(&v4_session.write_lock);
	if (error == -EPROTONOSUPPORT || error == -EOPNOTSUPP ||
	    error == -EPROTO)
		medusa_v4_mark_degraded(MEDUSA_HEALTH_PROTOCOL_ERROR);
out:
	kvfree(data);
	if (error) {
		medusa_protocol_counter_inc(MEDUSA_PROTOCOL_MALFORMED_MESSAGES);
		return error;
	}
	return count;
}

static __poll_t medusa_v4_poll(struct file *file, poll_table *wait)
{
	__poll_t mask = EPOLLOUT | EPOLLWRNORM;
	unsigned long flags;

	poll_wait(file, &v4_session.read_wait, wait);
	spin_lock_irqsave(&v4_session.queue_lock, flags);
	if (!list_empty(&v4_session.frames))
		mask |= EPOLLIN | EPOLLRDNORM;
	if (!v4_session.connected)
		mask |= EPOLLHUP;
	spin_unlock_irqrestore(&v4_session.queue_lock, flags);
	return mask;
}

static void medusa_v4_free_definitions(void)
{
	struct medusa_v4_class *class;
	struct medusa_v4_class *class_temporary;
	struct medusa_v4_event *event;
	struct medusa_v4_event *event_temporary;

	list_for_each_entry_safe(event, event_temporary,
				 &v4_session.events, node) {
		list_del(&event->node);
		kfree(event);
	}
	list_for_each_entry_safe(class, class_temporary,
				 &v4_session.classes, node) {
		list_del(&class->node);
		kfree(class);
	}
}

static int medusa_v4_open(struct inode *inode, struct file *file)
{
	int error;

	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;
	mutex_lock(&v4_session.state_lock);
	if (v4_session.connected) {
		mutex_unlock(&v4_session.state_lock);
		return -EBUSY;
	}
	medusa_v4_purge_frames();
	medusa_v4_free_definitions();
	v4_session.connected = true;
	v4_session.state = MEDUSA_STATE_HANDSHAKE;
	v4_session.enabled_features = 0;
	v4_session.expected_generation = 0;
	v4_session.next_class_id = 0;
	v4_session.next_event_id = 0;
	v4_session.replacing_policy = false;
	v4_session.owner_tgid = get_pid(task_tgid(current));
	medusa_v4_authserver.tgid = get_pid(task_tgid(current));
	file->private_data = &v4_session;
	medusa_server_health_mark_unhealthy(
		&constable_health, MEDUSA_HEALTH_DISCONNECTED);
	mutex_unlock(&v4_session.state_lock);

	error = med_register_authserver_prepare(&medusa_v4_authserver);
	if (!error)
		error = med_authserver_handshake_begin(&medusa_v4_authserver);
	if (error) {
		mutex_lock(&v4_session.state_lock);
		v4_session.connected = false;
		medusa_v4_free_definitions();
		put_pid(v4_session.owner_tgid);
		v4_session.owner_tgid = NULL;
		put_pid(medusa_v4_authserver.tgid);
		medusa_v4_authserver.tgid = NULL;
		mutex_unlock(&v4_session.state_lock);
		file->private_data = NULL;
	}
	return error;
}

static int medusa_v4_release(struct inode *inode, struct file *file)
{
	if (file->private_data != &v4_session)
		return 0;
	mutex_lock(&v4_session.write_lock);
	mutex_lock(&v4_session.state_lock);
	v4_session.connected = false;
	v4_session.state = MEDUSA_STATE_DISCONNECTED;
	medusa_server_health_mark_unhealthy(
		&constable_health, MEDUSA_HEALTH_DISCONNECTED);
	mutex_unlock(&v4_session.state_lock);
	med_unregister_authserver(&medusa_v4_authserver);
	medusa_decision_cache_reset();
	medusa_pending_request_cancel_all(MED_ERR);
	wake_up_all(&v4_session.read_wait);
	medusa_v4_purge_frames();
	mutex_lock(&v4_session.state_lock);
	medusa_v4_free_definitions();
	put_pid(v4_session.owner_tgid);
	v4_session.owner_tgid = NULL;
	put_pid(medusa_v4_authserver.tgid);
	medusa_v4_authserver.tgid = NULL;
	mutex_unlock(&v4_session.state_lock);
	mutex_unlock(&v4_session.write_lock);
	file->private_data = NULL;
	return 0;
}

static const struct file_operations medusa_v4_fops = {
	.owner = THIS_MODULE,
	.open = medusa_v4_open,
	.release = medusa_v4_release,
	.read = medusa_v4_read,
	.write = medusa_v4_write,
	.poll = medusa_v4_poll,
	.llseek = noop_llseek,
};

static struct miscdevice medusa_v4_device = {
	/*
	 * A stable minor lets an initramfs provide /dev/medusa before init can
	 * mount devtmpfs. This is required by the supported "start Constable
	 * before init" boot mode.
	 */
	.minor = MEDUSA_MISC_MINOR,
	.name = "medusa",
	.fops = &medusa_v4_fops,
	.mode = 0600,
};

static int __init medusa_v4_init(void)
{
	mutex_init(&v4_session.state_lock);
	mutex_init(&v4_session.read_lock);
	mutex_init(&v4_session.write_lock);
	spin_lock_init(&v4_session.queue_lock);
	init_waitqueue_head(&v4_session.read_wait);
	INIT_LIST_HEAD(&v4_session.frames);
	INIT_LIST_HEAD(&v4_session.classes);
	INIT_LIST_HEAD(&v4_session.events);
	v4_session.state = MEDUSA_STATE_DISCONNECTED;
	med_pr_info("registering protocol-v4 miscdevice /dev/medusa\n");
	return misc_register(&medusa_v4_device);
}

static void __exit medusa_v4_exit(void)
{
	misc_deregister(&medusa_v4_device);
}

module_init(medusa_v4_init);
module_exit(medusa_v4_exit);
MODULE_LICENSE("GPL");
