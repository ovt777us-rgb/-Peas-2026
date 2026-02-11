__author__ = 'Adam Rutherford'

import sys
import os
import hashlib
import errno
from random import choice
from string import ascii_uppercase, digits
from optparse import OptionParser

import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate, formataddr

import peas
from pathlib import Path, PureWindowsPath

R = '\033[1;31m'  # RED
G = '\033[0;32m'  # GREEN
Y = '\033[0;33m'  # YELLOW
M = '\033[0;35m'  # MAGENTA
S = '\033[0m'     # RESET


def info(msg):
    sys.stdout.write('{0}[*] {1}{2}\n'.format(G, msg, S))


def warning(msg):
    sys.stdout.write('{0}[!] {1}{2}\n'.format(Y, msg, S))


def error(msg):
    sys.stderr.write('{0}[-] {1}{2}\n'.format(R, msg, S))


def positive(msg):
    sys.stdout.write('{0}[+] {1}{2}\n'.format(G, msg, S))


def split_args(option, opt, value, parser):
    setattr(parser.values, option.dest, value.split(','))


def create_arg_parser():

    usage = "python -m peas [options] <server>"
    parser = OptionParser(usage=usage)

    # Settings:
    parser.add_option("-u", None, dest="user",
                      help="username", metavar="USER")

    parser.add_option("-p", None, dest="password",
                      help="password", metavar="PASSWORD")

    parser.add_option("-q", None, dest="quiet",
                      action="store_true", default=False,
                      help="suppress all unnecessary output")

    parser.add_option("--smb-user", None,
                      dest="smb_user",
                      help="username to use for SMB operations",
                      metavar="USER")

    parser.add_option("--smb-pass", None,
                      dest="smb_password",
                      help="password to use for SMB operations",
                      metavar="PASSWORD")

    parser.add_option("--verify-ssl", None, dest="verify_ssl",
                      action="store_true", default=False,
                      help="verify SSL certificates (important)")

    parser.add_option("-o", None, dest="file",
                      help="output to file", metavar="FILENAME")

    parser.add_option("-O", None, dest="output_dir",
                      help="output directory (for specific commands only, not combined with -o)", metavar="PATH")

    parser.add_option("-F", None, dest="format",
                      help="output formatting and encoding options",
                      metavar="repr,hex,b64,stdout,stderr,file")

    parser.add_option("--pattern", None, type="string", dest="pattern",
                      action="callback", callback=split_args,
                      help="filter files by comma-separated patterns (--crawl-unc)")

    parser.add_option("--download", None, dest="download",
                      action="store_true", default=False,
                      help="download files at a given UNC path while crawling (--crawl-unc)")

    parser.add_option("--prefix", None, dest="prefix",
                      help="NetBIOS hostname prefix (--brute-unc)")

    # Functionality:
    parser.add_option("--check", None,
                      action="store_true", dest="check",
                      help="check if account can be accessed with given password")

    parser.add_option("--emails", None,
                      action="store_true", dest="extract_emails",
                      help="retrieve emails")
                      
    parser.add_option("--search-emails", None,
                     dest="search_emails",
                     help="search emails by keywords (comma-separated)",
                     metavar="KEYWORDS")

    parser.add_option("--list-unc", None,
                      dest="list_unc",
                      help="list the files at a given UNC path",
                      metavar="UNC_PATH")
    
# ------- SHARE 1000+ BLOCK START -------
    parser.add_option("--unc-page-size", None,
                      dest="unc_page_size",
                      type="int", default=1000,
                      help="page size for UNC listing (Search Range window). Default: 1000")

    parser.add_option("--unc-max-items", None,
                      dest="unc_max_items",
                      type="int", default=50000,
                      help="stop UNC listing after N items. Default: 50000")

    parser.add_option("--debug-unc", None,
                      action="store_true", dest="debug_unc", default=False,
                      help="debug UNC paging (print Range/status per page)")
    # ------- SHARE 1000+ BLOCK END -------

    parser.add_option("--dl-unc", None,
                      dest="dl_unc",
                      help="download the file at a given UNC path",
                      metavar="UNC_PATH")

    parser.add_option("--crawl-unc", None,
                      dest="crawl_unc",
                      help="recursively list all files at a given UNC path",
                      metavar="UNC_PATH")

    parser.add_option("--brute-unc", None,
                      action="store_true", dest="brute_unc",
                      help="recursively list all files at a given UNC path")

    return parser


def init_authed_client(options, verify=True):

    if options.user is None:
        error("A username must be specified for this command.")
        return False
    if options.password is None:
        error("A password must be specified for this command.")
        return False

    client = peas.Peas()

    creds = {
        'server': options.server,
        'user': options.user,
        'password': options.password,
    }
    if options.smb_user is not None:
        creds['smb_user'] = options.smb_user
    if options.smb_password is not None:
        creds['smb_password'] = options.smb_password

    client.set_creds(creds)

    if not verify:
        client.disable_certificate_verification()

    return client


def check_server(options):

    client = peas.Peas()

    client.set_creds({'server': options.server})

    if not options.verify_ssl:
        client.disable_certificate_verification()

    result = client.get_server_headers()
    output_result(str(result), options, default='stdout')


def check(options):

    client = init_authed_client(options, verify=options.verify_ssl)
    if not client:
        return

    creds_valid = client.check_auth()
    if creds_valid:
        positive("Auth success.")
    else:
        error("Auth failure.")

# ------- EML FILES BLOCK START -------
_APPDATA_RE = re.compile(r'(<ApplicationData\b.*?>)(.*?)(</ApplicationData>)', re.I | re.S)


def _to_bytes(x):
    if isinstance(x, unicode):
        return x.encode('utf-8', 'replace')
    return x


def _split_application_data(blob):
    b = _to_bytes(blob)
    m = _APPDATA_RE.findall(b)
    if not m:
        return []
    out = []
    for start, mid, end in m:
        out.append(start + mid + end)
    return out


def _to_unicode(x):
    if x is None:
        return u''
    if isinstance(x, unicode):
        return x
    try:
        return x.decode('utf-8', 'replace')
    except Exception:
        try:
            return unicode(x)
        except Exception:
            return u''


_SAFE_FN_RE = re.compile(ur'[^A-Za-z0-9._ -]+', re.U)


def _safe_filename(name, fallback=u'email'):
    name = _to_unicode(name)
    name = name.strip().replace(u'/', u'-').replace(u'\\', u'-')
    name = _SAFE_FN_RE.sub(u'', name)
    name = re.sub(ur'\s+', u' ', name, flags=re.U).strip()
    if not name:
        name = fallback

    return name[:120]


def _extract_tag_text(app_bytes, tagname):
    r = re.search(r'<[^>]*%s[^>]*>(.*?)</[^>]*%s>' % (tagname, tagname), app_bytes, re.I | re.S)
    if not r:
        return None
    val = r.group(1)
    val = re.sub(r'<[^>]+>', '', val)
    val = re.sub(r'<([A-Za-z0-9._-]+)\s*/>', r'\1', val)
    val = val.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
    val = val.replace('/>', '').replace('<', '').replace('>', '')
    val = re.sub(r'\s+', ' ', val).strip()
    val = val.replace('/>', '')
    try:
        return val.decode('utf-8', 'replace') if isinstance(val, str) else val
    except Exception:
        return val


_EMAIL_RE = re.compile(r'([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}|[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+)')


def _clean_addr_text(s):
    s = _to_unicode(s)
    if not s:
        return None

    s = re.sub(ur'<([A-Za-z0-9._-]+)\s*/>', ur'\1', s, flags=re.U)

    s = s.replace(u'&lt;', u'<').replace(u'&gt;', u'>').replace(u'&amp;', u'&')

    s = re.sub(ur'<[^>]+>', u' ', s, flags=re.U)
    s = re.sub(ur'\s+', u' ', s, flags=re.U).strip()

    m = _EMAIL_RE.search(s)
    email_addr = m.group(1) if m else u''

    nm = re.search(ur'"([^"]+)"', s, flags=re.U)
    name = nm.group(1).strip() if nm else u''

    if email_addr and name and name != email_addr:
        return _to_unicode(formataddr((_to_bytes(name), _to_bytes(email_addr))))
    if email_addr:
        return email_addr
    return s or None


def _extract_body_html(app_bytes):
    b = _to_bytes(app_bytes)
    if not b:
        return u''

    m = re.search(r'<[^>]*airsyncbase:Body[^>]*>.*?<[^>]*airsyncbase:Data[^>]*>(.*?)</[^>]*airsyncbase:Data>',
                  b, re.I | re.S)
    if not m:
        m = re.search(r'<[^>]*:Data[^>]*>(.*?)</[^>]*:Data>', b, re.I | re.S)
        if not m:
            return u''

    body = _to_unicode(m.group(1))
    body = body.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')

    low = body.lower()

    p = low.find(u'<html')
    if p != -1:
        body = body[p:]
        low = body.lower()

    end_html = low.find(u'</html>')
    end_body = low.find(u'</body>')

    if end_html != -1 and (end_body == -1 or end_html < end_body):
        body = body[:end_html + len(u'</html>')]
        return body.strip()

    if end_body != -1:
        body = body[:end_body + len(u'</body>')]
        if u'</html>' not in body.lower():
            body += u'\n</html>'
        return body.strip()

    body = re.split(ur'(?is)<email:|<airsyncbase:|<email2:', body, 1)[0].strip()
    if body and u'</html>' not in body.lower():
        body += u'\n</html>'
    return body


def _parse_email_appdata(app_bytes):
    subject = _extract_tag_text(app_bytes, 'Subject')
    from_addr = _clean_addr_text(_extract_tag_text(app_bytes, 'From'))
    to_addr = _clean_addr_text(_extract_tag_text(app_bytes, 'To') or _extract_tag_text(app_bytes, 'DisplayTo'))
    date_val = _extract_tag_text(app_bytes, 'DateReceived')
    body_html = _extract_body_html(app_bytes)

    return {
        'subject': subject,
        'from_addr': from_addr,
        'to_addr': to_addr,
        'date': date_val,
        'body': body_html,
    }


def _write_eml(path, info):
    subject = info.get('subject')
    from_addr = info.get('from_addr')
    to_addr = info.get('to_addr')
    date_val = info.get('date')
    body = info.get('body') or u''

    if isinstance(body, str):
        body = body.decode('utf-8', 'replace')

    low = body.lower()
    is_html = (u'<html' in low) or (u'<body' in low)

    if is_html:
        msg = MIMEMultipart('alternative')
        plain = u'This message contains an HTML body. View in an HTML-capable mail client.\n'
        msg.attach(MIMEText(plain.encode('utf-8'), 'plain', 'utf-8'))
        msg.attach(MIMEText(body.encode('utf-8'), 'html', 'utf-8'))
    else:
        msg = MIMEText(body.encode('utf-8'), 'plain', 'utf-8')

    if subject:
        msg['Subject'] = subject.encode('utf-8') if isinstance(subject, unicode) else subject
    if from_addr:
        msg['From'] = from_addr.encode('utf-8') if isinstance(from_addr, unicode) else from_addr
    if to_addr:
        msg['To'] = to_addr.encode('utf-8') if isinstance(to_addr, unicode) else to_addr

    msg['Date'] = formatdate(localtime=True)
    if date_val:
        msg['X-Original-Date'] = date_val.encode('utf-8') if isinstance(date_val, unicode) else date_val

    with open(path, 'wb') as f:
        f.write(msg.as_string())
# ------- EML FILES BLOCK END -------


# ------- SEARCH BY KEYWORDS BLOCK START -------
# Display email search results in readable format
def output_search_results(results, options):
    if not options.quiet:
        print("[*] Found {0} emails".format(len(results)))
    
    if not results:
        return
    
    for i, email in enumerate(results, 1):
        if options.quiet:
            print("{0}|{1}|{2}|{3}".format(
                email.get('Date', ''),
                email.get('From', ''),
                email.get('Subject', ''),
                email.get('Body', '')[:100] if email.get('Body') else ''))
        else:
            print("\n[{0}] {1}".format(i, email.get('Subject', 'No subject')))
            print("From: {0}".format(email.get('From', 'N/A')))
            print("Date: {0}".format(email.get('Date', 'N/A')))
            body = email.get('Body', '') or email.get('Preview', '') or ''
            if body:
                print("Body: {0}...".format(body[:20]))


# Configure client with options
def setup_client(client, options):
    if options.verify_ssl:
        client.enable_certificate_verification()
    else:
        client.disable_certificate_verification()
    
    client.set_creds({
        'server': options.server,
        'user': options.user,
        'password': options.password
    })
    

# Search emails by keywords
def search_emails(options):
    client = peas.Peas()
    setup_client(client, options)
    
    try:
        results = client.search_emails(options.search_emails)
        output_search_results(results, options)
    except Exception as e:
        print("Search failed")
# ------- SEARCH BY KEYWORDS BLOCK END -------

# ------- EML FILES BLOCK START -------
def extract_emails(options):
    client = init_authed_client(options, verify=options.verify_ssl)
    if not client:
        return

    emails = client.extract_emails()

    if not options.output_dir:
        for email in emails:
            output_result(email + '\n', options, default='repr')
        return

    try:
        os.makedirs(options.output_dir)
    except OSError:
        pass

    idx = 0
    for blob in emails:
        appdatas = _split_application_data(blob)
        for app in appdatas:
            info_dict = _parse_email_appdata(app)

            digest = hashlib.md5(_to_bytes(app)).hexdigest()
            subj = _safe_filename(info_dict.get('subject'), fallback=u'email')
            fname = u'%s_%04d_%s.eml' % (subj, idx, digest[:8])

            path = os.path.join(options.output_dir, _to_bytes(fname))
            _write_eml(path, info_dict)

            idx += 1

    info("Wrote %d EML files to %r" % (idx, options.output_dir))

# ------- EML FILES BLOCK END -------

def list_unc_helper(client, uncpath, options, show_parent=True):
# ------- SHARE 1000+ BLOCK START -------
    records = client.get_unc_listing(uncpath,
                                     page_size=options.unc_page_size,
                                     max_items=options.unc_max_items,
                                     quiet=options.quiet,
                                     debug_paging=options.debug_unc)

    output = []
# ------- SHARE 1000+ BLOCK END -------
    if not options.quiet and show_parent:
        info("Listing: %s\n" % (uncpath,))

    for record in records:

        name = record.get('DisplayName')
        uncpath = record.get('LinkId')
        is_folder = record.get('IsFolder') == '1'
        is_hidden = record.get('IsHidden') == '1'
        size = record.get('ContentLength', '0') + 'B'
        ctype = record.get('ContentType', '-')
        last_mod = record.get('LastModifiedDate', '-')
        created = record.get('CreationDate', '-')

        attrs = ('f' if is_folder else '-') + ('h' if is_hidden else '-')

        output.append("%s %-24s %-24s %-24s %-12s %s" % (attrs, created, last_mod, ctype, size, uncpath))

    output_result('\n'.join(output), options, default='stdout')


def list_unc(options):

    client = init_authed_client(options, verify=options.verify_ssl)
    if not client:
        return

    list_unc_helper(client, options.list_unc, options)


def dl_unc(options):

    client = init_authed_client(options, verify=options.verify_ssl)
    if not client:
        return

    path = options.dl_unc
    data = client.get_unc_file(path)

    if not options.quiet:
        info("Downloading: %s\n" % (path,))

    output_result(data, options, default='repr')


def crawl_unc_helper(client, uncpath, patterns, options):
# ------- SHARE 1000+ BLOCK START -------
    records = client.get_unc_listing(uncpath,
                                     page_size=options.unc_page_size,
                                     max_items=options.unc_max_items,
                                     quiet=options.quiet,
                                     debug_paging=options.debug_unc)
# ------- SHARE 1000+ BLOCK END -------
    for record in records:
        if record['IsFolder'] == '1':
            if record['LinkId'] == uncpath:
                continue
            crawl_unc_helper(client, record['LinkId'], patterns, options)
        else:
            for pattern in patterns:
                if pattern.lower() in record['LinkId'].lower():
                    if options.download:
                        try:
                            data = client.get_unc_file(record['LinkId'])
                        except TypeError:
                            pass
                        else:
                            winpath = PureWindowsPath(record['LinkId'])
                            posixpath = Path(winpath.as_posix()) # Windows path to POSIX path
                            posixpath = Path(*posixpath.parts[1:]) # get rid of leading "/"
                            dirpath = posixpath.parent
                            newdirpath = mkdir_p(dirpath)
                            filename = str(newdirpath / posixpath.name)
                            try:
                                with open(filename, 'w') as fd:
                                    fd.write(data)
                            # If path name becomes too long when filename is added
                            except IOError as e:
                                if e.errno == errno.ENAMETOOLONG:
                                    rootpath = Path(newdirpath.parts[0])
                                    extname = posixpath.suffix
                                    # Generate random name for the file and put it in the root share directory
                                    filename = ''.join(choice(ascii_uppercase + digits) for _ in range(8)) + extname
                                    filename = str(rootpath / filename)
                                    with open(filename, 'w') as fd:
                                        fd.write(data)
                                    warning('File %s"%s"%s was renamed and written to %s"%s"%s' % (M, str(posixpath), S, M, filename, S))
                                else:
                                    raise
                            else:
                                if dirpath != newdirpath:
                                    warning('File %s"%s"%s was written to %s"%s"%s' % (M, str(posixpath), S, M, filename, S))

                    list_unc_helper(client, record['LinkId'], options, show_parent=False)

                    break


def crawl_unc(options):

    client = init_authed_client(options, verify=options.verify_ssl)
    if not client:
        return

    if options.pattern:
        patterns = options.pattern
    else:
        patterns = ['']

    if options.download:
        info('Listing and downloading all files: %s' % (options.crawl_unc,))
    else:
        info('Listing all files: %s' % (options.crawl_unc,))

    info('Pattern: %s\n' % (options.pattern,))

    crawl_unc_helper(client, options.crawl_unc, patterns, options)


def generate_wordlist(prefix=None):

    with open('hostnames.txt', 'r') as fd:
        hostnames = [line.strip() for line in fd]

    wordlist = []
    if prefix is not None:
        for h in hostnames:
            for i in range(1, 5):
                wordlist.append('{prefix}{i:02}-{h}'.format(prefix=prefix, i=i, h=h))  # PREFIX01-DC
                wordlist.append('{prefix}{i}-{h}'.format(prefix=prefix, i=i, h=h))     # PREFIX1-DC
                for j in range(1, 10):
                    wordlist.append('{prefix}{i:02}-{h}-{j:02}'.format(prefix=prefix, i=i, h=h, j=j))  # PREFIX01-DC-01
                    wordlist.append('{prefix}{i}-{h}-{j:02}'.format(prefix=prefix, i=i, h=h, j=j))     # PREFIX1-DC-01
                    wordlist.append('{prefix}{i:02}-{h}-{j}'.format(prefix=prefix, i=i, h=h, j=j))     # PREFIX01-DC-1
                    wordlist.append('{prefix}{i}-{h}-{j}'.format(prefix=prefix, i=i, h=h, j=j))        # PREFIX1-DC-1
                    wordlist.append('{prefix}{i:02}-{h}{j:02}'.format(prefix=prefix, i=i, h=h, j=j))   # PREFIX01-DC01
                    wordlist.append('{prefix}{i}-{h}{j:02}'.format(prefix=prefix, i=i, h=h, j=j))      # PREFIX1-DC01
                    wordlist.append('{prefix}{i:02}-{h}{j}'.format(prefix=prefix, i=i, h=h, j=j))      # PREFIX01-DC1
                    wordlist.append('{prefix}{i}-{h}{j}'.format(prefix=prefix, i=i, h=h, j=j))         # PREFIX1-DC1

    for h in hostnames:
        wordlist.append(h)  # DC
        for i in range(1, 10):
            wordlist.append('{h}-{i:02}'.format(h=h, i=i))  # DC-01
            wordlist.append('{h}-{i}'.format(h=h, i=i))     # DC-1
            wordlist.append('{h}{i:02}'.format(h=h, i=i))   # DC01
            wordlist.append('{h}{i}'.format(h=h, i=i))      # DC1

    return wordlist


def brute_unc(options):

    client = init_authed_client(options, verify=options.verify_ssl)
    if not client:
        return

    prefix = None
    if options.prefix:
        prefix = options.prefix.upper()

    wordlist = generate_wordlist(prefix)
    for w in wordlist:
        list_unc_helper(client, r'\\%s' % w, options, show_parent=False)


def output_result(data, options, default='repr'):

    fmt = options.format
    if not fmt:
        fmt = 'file' if options.file else default
    actions = fmt.split(',')

    # Write to file at the end if a filename is specified.
    if options.file and 'file' not in actions:
        actions.append('file')

    # Process the output based on the format/encoding options chosen.
    encoding_used = True
    for action in actions:
        if action == 'repr':
            data = repr(data)
            encoding_used = False
        elif action == 'hex':
            data = data.encode('hex')
            encoding_used = False
        elif action in ['base64', 'b64']:
            data = data.encode('base64')
            encoding_used = False
        elif action == 'stdout':
            print(data)
            encoding_used = True
        elif action == 'stderr':
            sys.stderr.write(data)
            encoding_used = True
        # Allow the user to write the file after other encodings have been applied.
        elif action == 'file':
            if options.file:
                open(options.file, 'wb').write(data)
                if not options.quiet:
                    info("Wrote %d bytes to %r." % (len(data), options.file))
            else:
                error("No filename specified.")
            encoding_used = True

    # Print now if an encoding has been used but never output.
    if not encoding_used:
        print(data)


def process_options(options):

    # Create the output directory if necessary.
    if options.output_dir:
        try:
            os.makedirs(options.output_dir)
        except OSError:
            pass

    return options


def mkdir_p(dirpath):

    try:
        dirname = str(dirpath)
        os.makedirs(dirname)
    except OSError as e:
        if e.errno == errno.EEXIST and os.path.isdir(dirname):
            pass
        # If directory path name already too long
        elif e.errno == errno.ENAMETOOLONG:
            dirpath = Path(dirpath.parts[0])
        else:
            raise

    return dirpath


def main():

    # Parse the arguments to the program into an options object.
    arg_parser = create_arg_parser()
    (options, args) = arg_parser.parse_args()

    if not options.quiet:
        peas.show_banner()

    options = process_options(options)

    # The server is required as an argument.
    if not args:
        arg_parser.print_help()
        return
    options.server = args[0]

    # Perform the requested functionality.
    ran = False
    if options.check:
        check(options)
        ran = True
    if options.extract_emails:
        extract_emails(options)
        ran = True
    if options.search_emails:
    	search_emails(options)
        ran = True
    if options.list_unc:
        list_unc(options)
        ran = True
    if options.dl_unc:
        dl_unc(options)
        ran = True
    if options.crawl_unc:
        crawl_unc(options)
        ran = True
    if options.brute_unc:
        brute_unc(options)
        ran = True
    if not ran:
        check_server(options)


if __name__ == '__main__':
    main()
