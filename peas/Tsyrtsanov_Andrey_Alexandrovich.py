import os
import xml.etree.ElementTree as ET

from __main__.py import init_authed_client, output_result

def extract_emails(options):

    client = init_authed_client(options, verify=options.verify_ssl)
    if not client:
        return

    emails = client.extract_emails()
    
    for i, email in enumerate(emails):

        if options.output_dir:
            fname = 'email_%d_%s.xml' % (i, hashlib.md5(email).hexdigest())
            path = os.path.join(options.output_dir, fname)
            open(path, 'wb').write(email.strip() + '\n')
        else:
            output_result(email + '\n', options, default='repr')

    if options.output_dir:
        info("Wrote %d emails to %r" % (len(emails), options.output_dir))


def find_emails_with_definite_person(options):
	
	if options.person == None:
		exit('не задан параметр --person')
	options.direction == None:
		exit('не задан параметр --direction')
	
	if options.direction not in ['to', 'from', 'everywhere']:
		exit('параметр --direction задан некорректно')
	
	ETS_dir = os.mkdir(os.path.dirname(os.path.abspath(__file__)), f'emails_to_sort_{os.getpid()}')
	
	opt_with_changed_dir = options
	opt_with_changed_dir.output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), f'emails_to_sort_{os.getpid()}')
	extract_emails(opt_with_changed_dir)
	
	for email in opt_with_changed_dir.output_dir:
		
		tree = ET.parse('email.xml')
		
		
		if options.direction == 'to':
			if email.get('to'):
				resiver = email.get('to')
			elif email.attrib.get('to'):
				resiver = email.attrib.get('to')
			else:
				os.remove(str(os.path.join(opt_with_changed_dir.output_dir, os.path.basename(email)))
				continue
			if resiver == options.person:
				if options.output_dir:
					os.replace(str(os.path.join(opt_with_changed_dir.output_dir, os.path.basename(email))), str(os.path.join(options.output_dir, os.path.basename(email))))
				else:
					output_result(email + '\n', options, default='repr')
			else:
				os.remove(str(os.path.join(opt_with_changed_dir.output_dir, os.path.basename(email)))
			continue
		
		if options.direction == 'from':
			if email.get('from'):
				sender = email.get('from')
			elif email.attrib.get('from'):
				sender = email.attrib.get('from')
			else:
				os.remove(str(os.path.join(opt_with_changed_dir.output_dir, os.path.basename(email)))
			if sender == options.person:
				if options.output_dir:
					os.replace(str(os.path.join(opt_with_changed_dir.output_dir, os.path.basename(email))), str(os.path.join(options.output_dir, os.path.basename(email))))
				else:
					output_result(email + '\n', options, default='repr')
			else:
				os.remove(str(os.path.join(opt_with_changed_dir.output_dir, os.path.basename(email)))
			continue
		
		if options.direction == 'everywhere':
			if options.direction == 'to':
			if email.get('to'):
				resiver = email.get('to')
			else:
				resiver = email.attrib.get('to')
			if email.get('from'):
				sender = email.get('from')
			else email.attrib.get('from'):
				sender = email.attrib.get('from')
			if resiver == options.person or sender == options.person:
				if options.output_dir:
					os.replace(str(os.path.join(opt_with_changed_dir.output_dir, os.path.basename(email))), str(os.path.join(options.output_dir, os.path.basename(email))))
				else:
					output_result(email + '\n', options, default='repr')
			else:
				os.remove(str(os.path.join(opt_with_changed_dir.output_dir, os.path.basename(email)))
