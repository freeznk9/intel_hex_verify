# -*- coding: utf-8 -*-

def prettyLine(intelHexLine) :
    rst = intelHexLine[0] + " " # start
    rst = rst + intelHexLine[1:3] + " " # byte count
    rst = rst + intelHexLine[3:7] + " " # Address
    rst = rst + intelHexLine[7:9] + " " # Recorrd Type
    rst = rst + intelHexLine[9:-2] + " " # Data
    rst = rst + intelHexLine[-2:] # CheckSum
    return rst

def ih2hexStrs(ih) :
    ih2 = {
        'Length' : format(ih['Length'], "02X"),
        'Address' : format(ih['Address'], '04X'),
        'RecordType' : format(ih['RecordType'], "02X"),
        'Data' : (''.join(format(x, '02X')+" " for x in ih['Data'])).strip(),
        'CheckSum' : format(ih['CheckSum'], "02X"),
        'CalcSum' : format(ih['CalcSum'], "02X")
    }
    return ih2

def verify_intel_hex_line(line, verbose=False) :
    if len(line) < 5 or line[0] != ':':
        return False, None
    buf = []
    for i in range(1, len(line), 2) :
        buf.append(int(line[i:i+2], 16))

    ih = {
        'Length' : buf[0],
        'Address' : ( (buf[1]<<8) | buf[2] ),
        'RecordType' : buf[3],
        #'Data' : buf[4:-1],
        #'CheckSum' : buf[-1],
        'Data' : None,
        'CheckSum' : None,
        'CalcSum' : None
    }

    if len(buf) < (5+ih['Length']) : # 5 : Length(1) + Address(2) + RecordType(1) + CheckSum(1)
        return False, ih

    ih['Data'] = buf[4:4+ih['Length']]
    ih['CheckSum'] = buf[4+ih['Length']]

    if ih['Length'] != len(ih['Data']) :
        return False, ih

    val = sum(buf[0:-1])
    val = ~val + 1
    val = val & 0xFF

    ih['CalcSum'] = val
    
    if verbose is True :
        print(ih)

    if ih['CalcSum'] != ih['CheckSum'] :
        if verbose is True :
            print("Failed! Checksum:{0} != Calc:{1}\n".format(ih['CheckSum'], ih['CalcSum']))
        return False, ih
    return True, ih

def verify_intel_hex(fn) :

    addrDoubtful = []
    addrLast = -999
    lengthLast = 0

    countOk = 0
    countError = 0
    with open(fn, 'r') as f:
        lineNo = 0
        while True:
            line = f.readline()
            lineNo = lineNo + 1
            if not line: break
            line = line.strip().replace(" ", "")
            ok, ih = verify_intel_hex_line(line, False)

            if addrLast != -999 and addrLast+lengthLast != ih['Address'] :
                addrDoubtful.append(lineNo)
                #print("ADDR WRONG?", format(lineNo, "4d"), format(addrLast,"04X"), format(lengthLast, "02X"), format(ih['Address'], "04X"))
            addrLast = ih['Address']
            lengthLast = ih['Length']
            
            if ok :
                countOk = countOk + 1
            else :
                countError = countError + 1
                print("# " + str(lineNo) + "\n" + prettyLine(line))
                #print(ih)
                print(ih2hexStrs(ih))
                print()
            if ih['RecordType'] == 0x01 :
                print("End of File Detected. Done.")
                break
    print("Address doubtful : ", len(addrDoubtful), " :  ", addrDoubtful)
    return countOk, countError

if __name__ == "__main__" :
    import sys, os

    if len(sys.argv) == 1:
        print("usage : " + sys.argv[0] + " {filename}")
        exit(1)

    if not os.path.exists(sys.argv[1]) :
        print("File Not Found. (" + sys.argv[1] + ")")
        exit(1)

    ok,err = verify_intel_hex(sys.argv[1])
    print("Result # OK:{0}, Error: {1}".format(ok,err))