fuzzy = ""
File.open("fuzzy", "r") do |f|
  fuzzy = f.read(33183)
end

puts(fuzzy.length)

start = fuzzy.index("\xAA\xB7\x76\x1A\xB7\x7C\x13\xDF")
puts("start = %x" % start)

start.upto(start + 0x6041E0 - 0x602160 - 1) do |i|
  fuzzy[i] = (fuzzy[i].ord ^ 0xFF).chr
end

File.open("fuzzy-decrypted", "w") do |f|
  f.write(fuzzy)
end
