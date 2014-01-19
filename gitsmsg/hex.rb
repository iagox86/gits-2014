class Hex
  def Hex.to_s(data)
    length = data.length
    out = ''

    0.upto(length - 1) do |i|

      if((i % 16) == 0)
        if(i != 0)
          out = out + "\n"
        end
        out = out + ("%04X" % i) + " " * 2
      end

      out = out + ("%02X " % data[i])

      if(((i + 1) % 16) == 0)
        out = out + (" " * 2)
        16.step(1, -1) do |j|
          out = out + ("%c" % ((data[i + 1 - j] > 0x20 && data[i + 1 - j] < 0x80) ? data[i + 1 - j] : ?.))
        end
      end

    end

    (length % 16).upto(16 - 1) do |i|
      out = out + ("   ") # The width of a hex character and a space
    end
    out = out + (' ' * 2)

    (length - (length % 16)).upto(length - 1) do |i|
      out = out + ("%c" % ((data[i] > 0x20 && data[i] < 0x80) ? data[i] : ?.))
    end

    out = out + ("\nLength: 0x%X (%d)\n" % [length, length])

    return out
  end

  def Hex.print(data)
    puts(Hex.to_s(data))
  end
end

