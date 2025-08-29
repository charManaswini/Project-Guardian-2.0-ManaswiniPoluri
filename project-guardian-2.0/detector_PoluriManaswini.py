import csv, json, re, ipaddress, spacy, sys

nlp = spacy.load("en_core_web_sm")

phone_re = re.compile(r'^[6-9]\d{9}$')
aadhar_re = re.compile(r'^\d{12}$')
passport_re = re.compile(r'^[A-Za-z][0-9]{7}$')
upi_re = re.compile(r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9]+$')
email_re = re.compile(r'^[^@]+@[^@]+\.[^@]+$')

def mask_phone(v): return v[:2]+'X'*(len(v)-6)+v[-4:] if len(v)==10 else '[REDACTED_PHONE]'
def mask_aadhar(v): return 'XXXX XXXX '+v[-4:] if len(v)==12 else '[REDACTED_AADHAAR]'
def mask_passport(v): return v[0]+'XXXXX'+v[-2:] if len(v)==8 else '[REDACTED_PASSPORT]'
def mask_upi(v): 
    p=v.split('@')
    return p[0][:2]+'*'*(len(p[0])-2)+'@'+p[1] if len(p)==2 else '[REDACTED_UPI]'
def mask_email(v): 
    l,d=v.split('@')
    return l[0]+'*'*(len(l)-1)+'@'+d
def mask_name(v): return ' '.join(p[0]+'X'*(len(p)-1) for p in v.split())
def mask_ip(v):
    try:
        ip=ipaddress.ip_address(v)
        if ip.version==4:
            s=v.split('.')
            return s[0]+'.'+s[1]+'.***.***'
        return v.split(':')[0]+'::****'
    except: return '[REDACTED_IP]'
def mask_address(v): return '[REDACTED_ADDRESS]'

def detect_regex(v):
    if phone_re.match(v): return ('phone',v)
    if aadhar_re.match(v): return ('aadhar',v)
    if passport_re.match(v): return ('passport',v)
    if upi_re.match(v) and any(p in v for p in ['upi','ybl','ok']): return ('upi',v)
    if email_re.match(v): return ('email',v)
    try: ipaddress.ip_address(v); return ('ip',v)
    except: pass
    if any(x in v.lower() for x in ['street','road','lane','sector','colony']): return ('address',v)
    return None

def detect_ner(v):
    doc=nlp(v)
    for ent in doc.ents:
        if ent.label_=='PERSON': return ('name',v)
        if ent.label_ in ['GPE','LOC']: return ('address',v)
    return None

def redact(val,typ):
    if typ=='phone': return mask_phone(val)
    if typ=='aadhar': return mask_aadhar(val)
    if typ=='passport': return mask_passport(val)
    if typ=='upi': return mask_upi(val)
    if typ=='email': return mask_email(val)
    if typ=='name': return mask_name(val)
    if typ=='ip': return mask_ip(val)
    if typ=='address': return mask_address(val)
    return val

def process_record(rid,data):
    try:
        d=json.loads(data)
    except json.JSONDecodeError:
        return rid,json.dumps({"raw_data": data}),False
    found={}
    for k,v in d.items():
        if not isinstance(v,str): continue
        r=detect_regex(v)
        if not r: r=detect_ner(v)
        if r: found.setdefault(r[0],[]).append(r[1])
    is_pii=False
    if any(t in found for t in ['phone','aadhar','passport','upi']): is_pii=True
    if sum(1 for t in ['name','email','address','ip'] if t in found)>=2: is_pii=True
    if is_pii:
        for t,vals in found.items():
            for val in vals:
                for k in d:
                    if isinstance(d[k],str) and d[k]==val:
                        d[k]=redact(val,t)
    return rid,json.dumps(d),is_pii

def main():
    infile=sys.argv[1] if len(sys.argv)>1 else 'iscp_pii_dataset.csv'
    outfile='redacted_output_PoluriManaswini.csv'
    with open(infile) as f, open(outfile,'w',newline='') as g:
        r=csv.reader(f); w=csv.writer(g)
        next(r); w.writerow(['record_id','redacted_data_json','is_pii'])
        for row in r:
            if len(row)<2: continue
            rid,dj=row[0],row[1]
            rid,rd,flag=process_record(rid,dj)
            w.writerow([rid, rd, str(flag)])



if __name__=='__main__':
    main()
