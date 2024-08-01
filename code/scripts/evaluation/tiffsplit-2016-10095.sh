rm -rf tiffsplit-2016-10095
rm -rf tiff-4.0.6.tar.gz
wget http://download.osgeo.org/libtiff/tiff-4.0.6.tar.gz
tar zxvf tiff-4.0.6.tar.gz
mv tiff-4.0.6 tiffsplit-2016-10095
cd tiffsplit-2016-10095; 
rm -rf obj-aflgo;
mkdir obj-aflgo; mkdir obj-aflgo/temp
export SUBJECT=$PWD; export TMP_DIR=$PWD/obj-aflgo/temp
export CC=$AFLGO/afl-clang-fast; export CXX=$AFLGO/afl-clang-fast++
export LDFLAGS=-lpthread
export ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
echo 'tif_dir.c:1056' > $TMP_DIR/BBtargets.txt
echo 'tif_dir.c:1056' > $TMP_DIR/real.txt
cd obj-aflgo; 
CFLAGS="-DFORTIFY_SOURCE=2 -fstack-protector-all -fno-omit-frame-pointer -g -Wno-error -func_trace=/transferfuzz/scripts/fuzz_functrace/cve-2016-10095.txt  $ADDITIONAL" LDFLAGS="-ldl -lutil" ../configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim --disable-ld
make clean; make
cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt
python3 /transferfuzz/scripts/generate_func_trace.py /transferfuzz/scripts/fuzz_functrace/cve-2016-10095.txt $TMP_DIR/edges_id.txt $TMP_DIR/Transfer_blocks.txt $TMP_DIR/Transfer_edges.txt
cd tools; 
$AFLGO/scripts/genDistance.sh $SUBJECT $TMP_DIR tiffsplit
cd ../../; 
rm -rf obj-dist;
mkdir obj-dist; 
cd obj-dist
cd obj-dist; # work around because cannot run make distclean
rm -rf $TMP_DIR/target_blocks.txt
CFLAGS="-DFORTIFY_SOURCE=2 -fstack-protector-all -fno-omit-frame-pointer -g -Wno-error -target_block=$TMP_DIR/Transfer_blocks.txt -outdir=$TMP_DIR -distance=$TMP_DIR/distance.cfg.txt" LDFLAGS="-ldl -lutil" ../configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim --disable-ld
make
python3 /transferfuzz/scripts/get_target_map.py -e $TMP_DIR/Transfer_edges.txt -b $TMP_DIR/target_blocks.txt -m $TMP_DIR/target_map.txt
rm -rf out
rm -rf in
mkdir in; 
echo "" > in/in
cp $SUBJECT/test/images/logluv-3c-16b.tiff in/tiff 
#$AFLGO/afl-fuzz -m none -c 45m -i in -o out binutils/cxxfilt
#$AFLGO/afl-fuzz -m none -c 45m -i in -o out -d -- tools/tiffsplit @@
$AFLGO/afl-fuzz -x /transferfuzz/scripts/fuzz_dict/cve-2016-10095.txt -R out/fuzz_record.txt -F $TMP_DIR/target_map.txt -m none -c 45m -i in -o out -d -- tools/tiffsplit @@
