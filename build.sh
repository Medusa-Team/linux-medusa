#!/bin/bash

PROGNAME=$0

if [ ! -f .dest ]; then
	echo -n "Please enter the rsync destination where the source codes should be copied (or leave blank for NONE): "
        read DEST
        echo $DEST > .dest
fi
DEST=`cat .dest`

minor=0
major=0

[ -f .minor ] && minor=`cat .minor`
[ -f .major ] && major=`cat .major`
echo $(($minor + 1)) > .minor

function do_exit {
        echo $2
        exit $1
}

function parse_argv {
        GRUB=1
        REBOOT=1
        MEDUSA_ONLY=0
        DELETE=0
        USE_RSYNC=1
        RSYNC_ONLY=0
        RUN_KUNIT=0

        for arg in "$@"; do
                if [[ "$arg" == '--delete' || "$arg" == '-delete' ]]; then
                        DELETE=1
                elif [[ "$arg" == '--clean' || "$arg" == '-clean' ]]; then
                        sudo make clean
                elif [[ "$arg" == '--nogdb' || "$arg" == '-nogdb' || "$arg" == '--nogrub' || "$arg" == '-nogrub' ]]; then
                        GRUB=0
                elif [[ "$arg" == '--noreboot' || "$arg" == '-noreboot' ]]; then
                        REBOOT=0
                elif [[ "$arg" == '--medusa-only' || "$arg" == '-medusa-only' ]]; then
                        MEDUSA_ONLY=1
                        GRUB=0
                elif [[ "$arg" == '--build-only' || "$arg" == '-build-only' ]]; then
                        GRUB=0
                        REBOOT=0
                elif [[ "$arg" == '--norsync' || "$arg" == '-norsync' ]]; then
                        USE_RSYNC=0
                elif [[ "$arg" == '--rsync-only' || "$arg" == '-rsync-only' ]]; then
                        RSYNC_ONLY=1
                elif [[ "$arg" == '--run-kunit' || "$arg" == '-run-kunit' ]]; then
                        RUN_KUNIT=1
                elif [[ "$arg" == '-h' || "$arg" == '--help' || "$arg" == '-help' ]]; then
                        help
                else
                        echo "Error unknown parameter '$arg'"
                        help
                fi
        done

        PROCESSORS=`cat /proc/cpuinfo | grep processor | wc -l`
}

function help {
        echo "$PROGNAME [--help] [--delete] [--clean] [--nogrub] [--nogdb] [--noreboot]";
        echo "    [--medusa-only] [--norsync] [--rsync-only] [--run-kunit]"
        echo "    --help           - Prints this help"
        echo "    --delete         - Deletes the medusa object files (handy when changing"
        echo "                       header files or makefiles)"
        echo "    --clean          - Does make clean before the compilation (handy when"
        echo "                       changing kernel release)"
        echo "    --nogrub/--nogdb - Turns off the waiting for GDB connection during booting"
        echo "    --noreboot       - Does not reboot at the end"
        echo "    --medusa-only    - Rebuilds just medusa not the whole kernel"
        echo "    --build-only     - Just rebuid the kernel(modue) no reboot no installation"
        echo "    --norsync        - Don't synchronize the sources on the debugging machine"
	echo ""
        echo "    --rsync-only     - Synchronizes the sources on the debugging machine, doesn't"
        echo "                       compile"
        echo "    --run-kunit      - Run available KUnit Medusa tests (this option overrides all"
        echo "                       other specified options and therefore are ignored)"
        exit 0
}

function delete_medusa {
        sudo find security/medusa/ -name '*.o' -delete
        sudo find security/medusa/ -name '*.cmd' -delete
}

function medusa_only {
        RELEASE="$(make kernelrelease)"
        make -j `expr $PROCESSORS + 1` security
        [ $? -ne 0 ] && do_exit 1 "make security failed"

        make -j `expr $PROCESSORS + 1` bzImage
        [ $? -ne 0 ] && do_exit 1 "make bzImage failed"
}

function run_kunit {
	cp .config .tmpconfig
	./tools/testing/kunit/kunit.py run
	cp .tmpconfig .config
	rm .tmpconfig
}

function install_module {
        CMD="sudo cp arch/x86/boot/bzImage /boot/vmlinuz-$RELEASE"
        eval $CMD
        [ $? -ne 0 ] && do_exit 1 "Copying of medusa module failed"

        CMD="sudo cp System.map /boot/System.map-$RELEASE"
        eval $CMD
        [ $? -ne 0 ] && do_exit 1 "Copying of System.map failed"

        CMD="sudo update-initramfs -u -k $RELEASE"
        eval $CMD
        [ $? -ne 0 ] && do_exit 1 "Update-initramfs failed"
}

function make_kernel {
	make -j `expr $PROCESSORS + 1`
        [ $? -ne 0 ] && do_exit 1 "make kernel failed"
}

function install_kernel {
	sudo make modules_install -j `expr $PROCESSORS + 1`
        [ $? -ne 0 ] && do_exit 1 "make modules_install failed"

	sudo make install
        [ $? -ne 0 ] && do_exit 1 "make install failed"
}

function rsync_repo {
        rsync -avz --exclude 'Documentation' --exclude '*.o' --exclude '.*' --exclude '*.cmd' --exclude '.git' --exclude '*.xz' --exclude '*tags' -e ssh . $DEST
}

function update_grub {
        temp=`mktemp XXXXXX`

        sudo cat /boot/grub/grub.cfg | while read line; do
                if [[ "$line" = */boot/vmlinuz-*medusa* ]]; then
                        echo "$line" | sed -e 's/quiet/kgdboc=ttyS0,115200 kgdbwait/' >> $temp
                else
                        echo "$line" >> $temp
                fi
        done

        sudo mv $temp /boot/grub/grub.cfg

        rm $temp 2> /dev/null
}

parse_argv $@

if [ $RUN_KUNIT -eq 1 ]; then
	run_kunit
	exit 0
fi

if [ $RSYNC_ONLY -eq 1 ]; then
	rsync_repo
	exit 0
fi

[ -f vmlinux ] && sudo rm -f vmlinux 2> /dev/null

[ $DELETE -eq 1 ] && delete_medusa

if [ $MEDUSA_ONLY -eq 1 ]; then
        medusa_only
else
        make_kernel
	install_kernel
fi

[ $USE_RSYNC -eq 1 ] && [ "$DEST" != "NONE" ] && rsync_repo

echo $(($major + 1)) > .major
echo 0 > .minor

echo $major.$minor >> myversioning

[ $GRUB -eq 1 ] && update_grub

[ $REBOOT -eq 1 ] && sudo reboot

