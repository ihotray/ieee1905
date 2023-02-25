
## README-fuzz-testing

This directory contains programs that can be used for fuzz testing of the 1905
stack. These programs must be built with `clang` and with the following CFLAGS and
LDFLAGS defined -

````bash
CFLAGS += -fsanitize=fuzzer,address
LDFLAGS += -fsanitize=fuzzer,address
````

The programs use LLVM libfuzzer and custom mutation to generate 1905 CMDU
structure-aware fuzzed payloads, which will not get rejected at the very first gate
of TLV validation function(s) within the 1905 stack.

Aditionally, the programs are prepared to run in their own address space,
independent of the 1905 stack.

### Build:
From the toplevel 1905 src directory, issue -

CC=clang make tests


### Run:
Example run of the 'rxcmdu' program, which simulates received 1905 CMDUs that
are fed into the stack via the 'rxcmdu' UBUS method -
````bash
~$ ./tests/fuzz/recv/rxcmdu -max_len=10000 -runs=1000000 -timeout=3000 -len_control=200 -print_final_stats=1
````

The above command will allow generation of CMDUs up to `max_len 10000`, run the
fuzzing tests for `1000000 iterations`, with each run limited to `timeout 3000ms`.

Refer to *https://llvm.org/docs/LibFuzzer.html* for information about all
supported arguments that each program here can take.

**NOTE** 1905 stack (i.e. `ieee1905d`) must be running before the above command can
be run for fuzz testing.

### Output from above run:

````bash
INFO: Seed: 4045601530
INFO: Loaded 1 modules   (93 inline 8-bit counters): 93 [0x5a9ea0, 0x5a9efd),
INFO: Loaded 1 PC tables (93 PCs): 93 [0x56c910,0x56cee0),
INFO: A corpus is not provided, starting from an empty corpus
#2	INITED cov: 10 ft: 11 corp: 1/1b exec/s: 0 rss: 29Mb
	NEW_FUNC[1/5]: 0x54fab0 in blobmsg_add_string /usr/include/libubox/blobmsg.h:222
	NEW_FUNC[2/5]: 0x54fb60 in blobmsg_add_u32 /usr/include/libubox/blobmsg.h:208
#3	NEW    cov: 24 ft: 26 corp: 2/4b lim: 4 exec/s: 0 rss: 30Mb L: 3/3 MS: 1 Custom-
#4	NEW    cov: 26 ft: 30 corp: 3/7b lim: 4 exec/s: 0 rss: 30Mb L: 3/3 MS: 1 Custom-
#6	NEW    cov: 26 ft: 31 corp: 4/10b lim: 4 exec/s: 0 rss: 30Mb L: 3/3 MS: 2 Custom-Custom-
#10	NEW    cov: 27 ft: 32 corp: 5/13b lim: 4 exec/s: 0 rss: 30Mb L: 3/3 MS: 6 ChangeBit-Custom-Custom-ChangeByte-Custom-Custom-
#14	NEW    cov: 27 ft: 34 corp: 6/16b lim: 4 exec/s: 0 rss: 31Mb L: 3/3 MS: 5 Custom-Custom-Custom-CopyPart-Custom-
#20	NEW    cov: 30 ft: 37 corp: 7/20b lim: 4 exec/s: 0 rss: 31Mb L: 4/4 MS: 2 CrossOver-Custom-
#28	NEW    cov: 30 ft: 38 corp: 8/22b lim: 4 exec/s: 0 rss: 32Mb L: 2/4 MS: 4 Custom-Custom-EraseBytes-Custom-
#415	NEW    cov: 31 ft: 39 corp: 9/25b lim: 4 exec/s: 0 rss: 56Mb L: 3/4 MS: 3 Custom-ChangeBit-Custom-
#663	REDUCE cov: 31 ft: 39 corp: 9/22b lim: 4 exec/s: 0 rss: 71Mb L: 1/3 MS: 4 Custom-Custom-CrossOver-Custom-
#780	REDUCE cov: 31 ft: 39 corp: 9/21b lim: 4 exec/s: 0 rss: 78Mb L: 2/3 MS: 3 Custom-EraseBytes-Custom-
#1254	REDUCE cov: 31 ft: 40 corp: 10/27b lim: 6 exec/s: 0 rss: 107Mb L: 6/6 MS: 6 ChangeByte-Custom-Custom-Custom-CrossOver-Custom-
#2271	NEW    cov: 31 ft: 41 corp: 11/38b lim: 11 exec/s: 0 rss: 169Mb L: 11/11 MS: 3 Custom-CrossOver-Custom-
#2878	NEW    cov: 36 ft: 48 corp: 12/47b lim: 14 exec/s: 0 rss: 206Mb L: 9/11 MS: 2 Custom-Custom-
#3710	NEW    cov: 36 ft: 49 corp: 13/56b lim: 17 exec/s: 0 rss: 257Mb L: 9/11 MS: 2 Custom-Custom-
#4032	NEW    cov: 36 ft: 50 corp: 14/67b lim: 17 exec/s: 0 rss: 277Mb L: 11/11 MS: 4 ShuffleBytes-Custom-ShuffleBytes-Custom-
#4274	NEW    cov: 36 ft: 51 corp: 15/84b lim: 17 exec/s: 0 rss: 291Mb L: 17/17 MS: 3 Custom-CrossOver-Custom-
#5290	REDUCE cov: 36 ft: 51 corp: 15/83b lim: 21 exec/s: 0 rss: 344Mb L: 16/16 MS: 2 EraseBytes-Custom-
#5460	REDUCE cov: 37 ft: 52 corp: 16/101b lim: 21 exec/s: 0 rss: 344Mb L: 18/18 MS: 5 Custom-Custom-Custom-Custom-Custom-
#5600	NEW    cov: 37 ft: 54 corp: 17/119b lim: 21 exec/s: 5600 rss: 344Mb L: 18/18 MS: 5 Custom-Custom-Custom-Custom-Custom-
#6062	NEW    cov: 37 ft: 58 corp: 18/137b lim: 21 exec/s: 6062 rss: 344Mb L: 18/18 MS: 3 ShuffleBytes-Custom-Custom-
#9793	REDUCE cov: 37 ft: 60 corp: 19/172b lim: 38 exec/s: 9793 rss: 344Mb L: 35/35 MS: 2 InsertRepeatedBytes-Custom-
#11620	REDUCE cov: 37 ft: 64 corp: 20/191b lim: 43 exec/s: 11620 rss: 344Mb L: 19/35 MS: 2 Custom-Custom-
#13678	NEW    cov: 37 ft: 68 corp: 21/214b lim: 53 exec/s: 6839 rss: 344Mb L: 23/35 MS: 3 Custom-Custom-Custom-
#14224	REDUCE cov: 37 ft: 69 corp: 22/264b lim: 53 exec/s: 7112 rss: 344Mb L: 50/50 MS: 2 InsertRepeatedBytes-Custom-
#16384	pulse  cov: 37 ft: 69 corp: 22/264b lim: 63 exec/s: 8192 rss: 344Mb
#17755	REDUCE cov: 37 ft: 69 corp: 22/262b lim: 68 exec/s: 8877 rss: 344Mb L: 14/50 MS: 2 EraseBytes-Custom-
#18641	REDUCE cov: 37 ft: 69 corp: 22/261b lim: 68 exec/s: 9320 rss: 344Mb L: 10/50 MS: 2 EraseBytes-Custom-
#21322	REDUCE cov: 37 ft: 69 corp: 22/260b lim: 80 exec/s: 10661 rss: 344Mb L: 8/50 MS: 2 EraseBytes-Custom-
#24267	REDUCE cov: 37 ft: 69 corp: 22/259b lim: 92 exec/s: 8089 rss: 344Mb L: 49/49 MS: 6 Custom-Custom-Custom-Custom-InsertRepeatedBytes-Custom-
#29134	NEW    cov: 37 ft: 70 corp: 23/331b lim: 116 exec/s: 9711 rss: 344Mb L: 72/72 MS: 3 Custom-InsertRepeatedBytes-Custom-
#31605	REDUCE cov: 37 ft: 71 corp: 24/459b lim: 128 exec/s: 7901 rss: 344Mb L: 128/128 MS: 2 CrossOver-Custom-
#32768	pulse  cov: 37 ft: 71 corp: 24/459b lim: 128 exec/s: 8192 rss: 344Mb
#65536	pulse  cov: 37 ft: 71 corp: 24/459b lim: 293 exec/s: 8192 rss: 345Mb
#81788	REDUCE cov: 37 ft: 71 corp: 24/451b lim: 373 exec/s: 8178 rss: 345Mb L: 120/120 MS: 4 Custom-Custom-InsertRepeatedBytes-Custom-
#91869	REDUCE cov: 37 ft: 71 corp: 24/450b lim: 421 exec/s: 7655 rss: 346Mb L: 1/120 MS: 2 EraseBytes-Custom-
#101810	REDUCE cov: 37 ft: 71 corp: 24/445b lim: 469 exec/s: 7831 rss: 346Mb L: 115/115 MS: 2 EraseBytes-Custom-
#116191	REDUCE cov: 37 ft: 71 corp: 24/429b lim: 535 exec/s: 7746 rss: 346Mb L: 99/99 MS: 2 EraseBytes-Custom-
#128679	REDUCE cov: 37 ft: 71 corp: 24/428b lim: 589 exec/s: 8042 rss: 346Mb L: 13/99 MS: 4 Custom-Custom-CrossOver-Custom-
#131072	pulse  cov: 37 ft: 71 corp: 24/428b lim: 598 exec/s: 7710 rss: 346Mb
#155750	REDUCE cov: 37 ft: 71 corp: 24/426b lim: 715 exec/s: 7787 rss: 347Mb L: 9/99 MS: 2 EraseBytes-Custom-
#168596	REDUCE cov: 37 ft: 71 corp: 24/425b lim: 778 exec/s: 7663 rss: 347Mb L: 12/99 MS: 2 EraseBytes-Custom-
#178097	REDUCE cov: 37 ft: 71 corp: 24/424b lim: 823 exec/s: 7743 rss: 347Mb L: 9/99 MS: 2 EraseBytes-Custom-
#196938	REDUCE cov: 37 ft: 71 corp: 24/423b lim: 913 exec/s: 7877 rss: 347Mb L: 34/99 MS: 2 EraseBytes-Custom-
#225610	NEW    cov: 38 ft: 72 corp: 25/1473b lim: 1050 exec/s: 7779 rss: 348Mb L: 1050/1050 MS: 3 Custom-CrossOver-Custom-
#248906	REDUCE cov: 38 ft: 72 corp: 25/1464b lim: 1160 exec/s: 7778 rss: 348Mb L: 25/1050 MS: 2 EraseBytes-Custom-
#262144	pulse  cov: 38 ft: 72 corp: 25/1464b lim: 1220 exec/s: 7710 rss: 348Mb
#268632	NEW    cov: 39 ft: 73 corp: 26/2714b lim: 1250 exec/s: 7675 rss: 348Mb L: 1250/1250 MS: 2 CrossOver-Custom-
#278718	REDUCE cov: 39 ft: 74 corp: 27/4014b lim: 1300 exec/s: 7742 rss: 348Mb L: 1300/1300 MS: 2 CrossOver-Custom-
#282734	REDUCE cov: 39 ft: 74 corp: 27/4013b lim: 1320 exec/s: 7853 rss: 348Mb L: 98/1300 MS: 2 EraseBytes-Custom-
#313390	REDUCE cov: 39 ft: 75 corp: 28/5483b lim: 1470 exec/s: 7643 rss: 349Mb L: 1470/1470 MS: 2 CrossOver-Custom-
#315366	REDUCE cov: 39 ft: 75 corp: 28/5399b lim: 1470 exec/s: 7691 rss: 349Mb L: 1216/1470 MS: 2 EraseBytes-Custom-
#524288	pulse  cov: 39 ft: 75 corp: 28/5399b lim: 2512 exec/s: 7598 rss: 351Mb
#597156	REDUCE cov: 39 ft: 75 corp: 28/5384b lim: 2875 exec/s: 7558 rss: 352Mb L: 3/1470 MS: 6 Custom-Custom-Custom-Custom-ChangeBinInt-Custom-
#729337	NEW    cov: 39 ft: 76 corp: 29/5402b lim: 3524 exec/s: 7367 rss: 353Mb L: 18/1470 MS: 2 CopyPart-Custom-
#743890	NEW    cov: 39 ft: 77 corp: 30/8992b lim: 3590 exec/s: 7365 rss: 354Mb L: 3590/3590 MS: 4 Custom-Custom-CrossOver-Custom-
#842151	REDUCE cov: 39 ft: 77 corp: 30/8991b lim: 4074 exec/s: 7323 rss: 355Mb L: 48/3590 MS: 2 EraseBytes-Custom-
#886932	REDUCE cov: 39 ft: 77 corp: 30/8989b lim: 4288 exec/s: 7269 rss: 355Mb L: 96/3590 MS: 2 EraseBytes-Custom-
#949368	REDUCE cov: 39 ft: 77 corp: 30/7832b lim: 4588 exec/s: 7192 rss: 355Mb L: 2433/2433 MS: 2 EraseBytes-Custom-
#1000000	DONE   cov: 39 ft: 77 corp: 30/7832b lim: 4840 exec/s: 7194 rss: 355Mb
Done 1000000 runs in 139 second(s)
stat::number_of_executed_units: 1000000
stat::average_exec_per_sec:     7194
stat::new_units_added:          52
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              355
````


