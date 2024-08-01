#rm -rf swftopython-CVE-2018-8807
git clone https://github.com/libming/libming.git swftopython-CVE-2018-8807
cd swftopython-CVE-2018-8807/; git checkout b72cc2f # version 0.4.8
rm -rf obj-aflgo
mkdir obj-aflgo; mkdir obj-aflgo/temp
export SUBJECT=$PWD; export TMP_DIR=$PWD/obj-aflgo/temp
export CC=$AFLGO/afl-clang-fast; export CXX=$AFLGO/afl-clang-fast++
export LDFLAGS=-lpthread
export ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
echo 'decompile.c:349' > $TMP_DIR/BBtargets.txt
echo 'decompile.c:349' > $TMP_DIR/real.txt
./autogen.sh;
cd obj-aflgo; CFLAGS="-func_trace=/transferfuzz/scripts/fuzz_functrace/cve-2018-8807.txt -g $ADDITIONAL" CXXFLAGS="-func_trace=/transferfuzz/scripts/fuzz_functrace/cve-2018-8807.txt -g $ADDITIONAL" ../configure --disable-shared --prefix=`pwd`
make clean; make
cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt
python3 /transferfuzz/scripts/generate_func_trace.py /transferfuzz/scripts/fuzz_functrace/cve-2018-8807.txt $TMP_DIR/edges_id.txt $TMP_DIR/Transfer_blocks.txt $TMP_DIR/Transfer_edges.txt
cd util; 
$AFLGO/scripts/genDistance.sh $SUBJECT $TMP_DIR swftopython
rm -rf $TMP_DIR/target_blocks.txt
cd -; CFLAGS="-target_block=$TMP_DIR/Transfer_blocks.txt -outdir=$TMP_DIR -g -distance=$TMP_DIR/distance.cfg.txt" CXXFLAGS="-target_block=$TMP_DIR/Transfer_blocks.txt -outdir=$TMP_DIR -g -distance=$TMP_DIR/distance.cfg.txt" ../configure --disable-shared --prefix=`pwd`
make clean; make
python3 /transferfuzz/scripts/get_target_map.py -e $TMP_DIR/Transfer_edges.txt -b $TMP_DIR/target_blocks.txt -m $TMP_DIR/target_map.txt
rm -rf in out
mkdir in; 
wget -P in --no-check-certificate http://condor.depaul.edu/sjost/hci430/flash-examples/swf/bumble-bee1.swf
echo ' ' >in/tmp.swf
$AFLGO/afl-fuzz -R out/fuzz_record.txt -F $TMP_DIR/target_map.txt -m none -z exp -c 45m -i in -o out -d ./util/swftopython @@
#$AFLGO/afl-fuzz -i in -o out -m none -t 9999 -d -- ./util/swftopython @@

