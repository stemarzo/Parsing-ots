HEADER_MAGIC=b'\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94'
VERSION=b'\x01'

#TAG OPERAZIONI
APPEND=b'\xf0'
PREPEND=b'\xf1'
REVERSE=b'\xf2'
HEXLIFY=b'\xf3'

#TAG TIPI HASH
SHA1=b'\x02'
RIPEMD160=b'\x03'
SHA256=b'\x08'
KEKKAK256=b'\x67'

INIZIO=b'\x00'
FINE=b'\xff'

#TAG ATTESTAZIONI
PENDING_ATTESTATION=b'\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e'
BITCOIN=b'\x05\x88\x96\x0d\x73\xd7\x19\x01'
LITECOIN=b'\x06\x86\x9a\x0d\x73\xd7\x1b\x45'
ETHEREUM=b'\x30\xfe\x80\x87\xb5\xc7\xea\xd7'

LENGTH_256=32
LENGTH_160=20
LENGHT_HASH=0

LENGTH_TAG_ATTESTATION=8
LENGTH_HASH_OPERATION_TAG=1

NULLO=b''


class Operazione:
    def __init__(self, nomeOp, lunghezzaStringa, stringaOperazione, attestazione):
        self.nomeOp=nomeOp
        self.lunghezzaStringa=lunghezzaStringa
        self.stringaOperazione=stringaOperazione
        self.attestazione=attestazione
        
    def __str__(self):
        return(self.nomeOp+" "+str(self.stringaOperazione))

class BloccoAtt:
    def __init__(self, blocco, flagAttestazione):
        self.blocco=blocco
        self.flagAttestazione=flagAttestazione
    def __str__(self):
        s=""
        if self.flagAttestazione==0:
            for operazione in self.blocco:
                s+=operazione.__str__()+"\n"
        else:
            for operazione in self.blocco:
                s+="\t"+operazione.__str__()+"\n"
        return s   


def tagToName(tag):
  switcher = {
    APPEND: "append",
    PREPEND: "prepend",
    REVERSE: "reverse",
    HEXLIFY: "Hexlify",
    SHA1: "SHA1",
    SHA256: "SHA256",
    RIPEMD160: "RIPEMD160",
    KEKKAK256: "KEKKAK256",
    PENDING_ATTESTATION: "Pending Attestation",
    BITCOIN: "Bitcoin block header Attestation",
    LITECOIN: "Litecoin block header Attestation",
    ETHEREUM: "Ethereum block header Attestation"
  }
  return switcher.get(tag, None)

def nameToTag(nome):
  switcher = {
    "append": APPEND,
    "prepend": PREPEND,
    "reverse": REVERSE,
    "Hexlify": HEXLIFY,
    "SHA1": SHA1,
    "SHA256": SHA256,
    "RIPEMD160": RIPEMD160,
    "KEKKAK256": KEKKAK256,
    "Pending Attestation": PENDING_ATTESTATION,
    "Bitcoin block header Attestation": BITCOIN,
    "Litecoin block header Attestation": LITECOIN,
    "Ethereum block header Attestation": ETHEREUM
  }
  return switcher.get(nome, None)

FILE_OTS = {
    "magic number": "",
    "version": "",
    "operazione hash usata": "",
    "hash file": "",
    "timestamp": "",
}

#Prova da parsare
f=open("examples/prova.ots", "rb")




def deserialize(f):
    #Magic number
    mnumber=f.read(len(HEADER_MAGIC))
    if mnumber == HEADER_MAGIC:
        FILE_OTS["magic number"]=mnumber
    else:
        print("Formato non riconosciuto")

    #Version
    version=f.read(len(VERSION))
    if version == VERSION:
        FILE_OTS["version"]=version.hex()
    else:
        print("Versione non supportata")

    #Operazione di hash
    ophash=f.read(LENGTH_HASH_OPERATION_TAG)
    if ophash == SHA256 or ophash==KEKKAK256 :
        FILE_OTS["operazione hash usata"]= tagToName(ophash)
        LENGHT_HASH=LENGTH_256
    elif ophash==SHA1 or ophash==RIPEMD160:
        FILE_OTS["operazione hash usata"]= tagToName(ophash)
        LENGHT_HASH=LENGTH_160
    else:
        print("Versione non supportata")

    #Hash del file
    hashfile=f.read(LENGHT_HASH)
    FILE_OTS["hash file"]= hashfile.hex()

    #deserialize timestamp
    blocco=[]
    blocchi=[]

    tag=f.read(1)
    while tag != NULLO:
        if tag==APPEND or tag==PREPEND:
            nomeOp=tagToName(tag)
            lunghezzaStringa=int(f.read(1).hex(), 16)
            stringaOperazione=f.read(lunghezzaStringa).hex()
            operazione=Operazione(nomeOp,lunghezzaStringa,stringaOperazione, 0)
            blocco.append(operazione)
            tag=f.read(1)
        elif tag==SHA1 or tag==SHA256 or tag==RIPEMD160 or tag==KEKKAK256:
            nomeOp=tagToName(tag)
            lunghezzaStringa=0
            stringaOperazione=""
            operazione=Operazione(nomeOp,lunghezzaStringa,stringaOperazione, 0)
            blocco.append(operazione)
            tag=f.read(1)
        elif tag==INIZIO:
            tagAttestazione=f.read(LENGTH_TAG_ATTESTATION)
            lunghezzaPayload=int(f.read(1).hex(), 16)
            attestazione=Operazione(tagToName(tagAttestazione),lunghezzaPayload,f.read(lunghezzaPayload), 1)
            blocco.append(attestazione)
            bloccoatt=BloccoAtt(blocco, 1)
            blocchi.append(bloccoatt)
            blocco=[]
            tag=f.read(1)
        elif tag==FINE:
            tag=f.read(1)
            if tag==INIZIO:
                tagAttestazione=f.read(LENGTH_TAG_ATTESTATION)
                lunghezzaPayload=int(f.read(1).hex(), 16)
                attestazione=Operazione(tagToName(tagAttestazione),lunghezzaPayload,f.read(lunghezzaPayload),1)
                blocco.append(attestazione)
                tag=f.read(1)
            else:
                if len(blocco)!=0:
                    bloccoatt=BloccoAtt(blocco, 0)
                    blocchi.append(bloccoatt)
                    blocco=[]
    FILE_OTS["timestamp"]=blocchi










def stampaFileOts():
    s="Versione -> "+FILE_OTS["version"]+"\n"
    s+="Operazione di hash usata -> "+FILE_OTS["operazione hash usata"]+"\n"
    s+="Hash del file -> "+FILE_OTS["hash file"]+"\n"
    s+="OPERAZIONI\n"
    for block in FILE_OTS["timestamp"]:
        s+=block.__str__()+"\n"
    return(s)




def serialize():
    ots=b""
    ots+=FILE_OTS["magic number"]
    ots+=bytes.fromhex(FILE_OTS["version"])
    ots+=nameToTag(FILE_OTS["operazione hash usata"])
    ots+=bytes.fromhex(FILE_OTS["hash file"])
    numeroFine=len(FILE_OTS["timestamp"])-2
    for blocco in FILE_OTS["timestamp"]:
        i=1
        for operazione in blocco.blocco:
            if operazione.attestazione==0:
                ots+=nameToTag(operazione.nomeOp)
                if operazione.lunghezzaStringa != 0:
                    ots+=bytes([operazione.lunghezzaStringa])
                    ots+=bytes.fromhex(operazione.stringaOperazione)
            if operazione.attestazione == 1:
                if i<len(blocco.blocco):
                    ots+=FINE
                ots+=INIZIO
                ots+=nameToTag(operazione.nomeOp)
                ots+=bytes([operazione.lunghezzaStringa])
                ots+=operazione.stringaOperazione
            i+=1
        if numeroFine>0:
            numeroFine-=1
            ots+=FINE
    return ots


deserialize(f)
print(stampaFileOts())




with open('mia.ots', 'wb') as f:
    f.write(serialize())
