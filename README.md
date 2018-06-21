# afl-manager
- Manager multi-afl by python server
https://zx1340.wordpress.com/2017/11/19/afl-manager/


#Using:

python server.py --help


>usage: server.py [-h] -i INPUT_DATA -b BINARY [-c ASAN_BINARY] -x DICTIONARY
>                 -a AUTHEN [-q]

>AFL Manager

>optional arguments:
 * -h, --help      show this help message and exit
 * -i [INPUT_DATA]   Parent directory of AFL
 * -b [BINARY]       binary
 * -c [ASAN_BINARY]  Asan binary
 * -x [DICTIONARY]   Dictionary file
 * -a [AUTHEN]       Authencation user:pass
 * -q, [--queue]     Show queue
