# -*- coding: utf-8 -*-

def prettyLine(intelHexLine) :
    rst = intelHexLine[0] + " " # start
    rst = rst + intelHexLine[1:3] + " " # byte count
    rst = rst + intelHexLine[3:7] + " " # Address
    rst = rst + intelHexLine[7:9] + " " # Recorrd Type
    rst = rst + intelHexLine[9:-2] + " " # Data
    rst = rst + intelHexLine[-2:] # CheckSum
    return rst

def verify_intel_hex_conv_pretty(fn, fn2) :
    with open(fn2, 'w') as f2 :
        with open(fn, 'r') as f:
            while True:
                line = f.readline()
                line = line.strip()
                if not line: break
                if line[0] == ":" :
                    f2.write(prettyLine(line) + "\n")
                else :
                    f2.write(line + "\n")
            

if __name__ == "__main__" :
    import sys, os

    if len(sys.argv) < 3:
        print("usage : " + sys.argv[0] + " {filename} {output_filename}")
        exit(1)

    if not os.path.exists(sys.argv[1]) :
        print("File Not Found. (" + sys.argv[1] + ")")
        exit(1)

    verify_intel_hex_conv_pretty(sys.argv[1], sys.argv[2])