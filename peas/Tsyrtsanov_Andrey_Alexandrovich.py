import os
import xml.etree.ElementTree as ET
from datetime import datetime

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
	if options.direction == None:
		exit('не задан параметр --direction')
	
	if options.direction not in ['to', 'from', 'everywhere']:
		exit('параметр --direction задан некорректно')
	
	ETS_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), f'emails_to_sort_{os.getpid()}')
	os.mkdir(ETS_dir)
	
	opt_with_changed_dir = options
	opt_with_changed_dir.output_dir = ETS_dir
	extract_emails(opt_with_changed_dir)
	
	for email in ETS_dir:
		
		tree = ET.parse('email.xml')
		root = tree.getroot()
		
		
		if options.direction == 'to':
			if root.find('to').text:
				resiver = root.find('to').text
			elif root.attrib.get('to'):
				resiver = root.attrib.get('to')
			else:
				os.remove(str(os.path.join(ETS_dir, os.path.basename(email))))
				continue
			if resiver == options.person:
				if options.output_dir:
					os.replace(str(os.path.join(ETS_dir, os.path.basename(email))), str(os.path.join(options.output_dir, os.path.basename(email))))
				else:
					output_result(email + '\n', options, default='repr')
			else:
				os.remove(str(os.path.join(ETS_dir, os.path.basename(email))))
			continue
		
		if options.direction == 'from':
			if root.find('from').text:
				sender = root.find('from').text
			elif root.attrib.get('from'):
				sender = root.attrib.get('from')
			else:
				os.remove(str(os.path.join(ETS_dir, os.path.basename(email))))
			if sender == options.person:
				if options.output_dir:
					os.replace(str(os.path.join(ETS_dir, os.path.basename(email))), str(os.path.join(ETS_dir, os.path.basename(email))))
				else:
					output_result(email + '\n', options, default='repr')
			else:
				os.remove(str(os.path.join(ETS_dir, os.path.basename(email))))
			continue
		
		if options.direction == 'everywhere':
			if options.direction == 'to':
				if root.find('to').text:
					resiver = root.find('to').text
			else:
				resiver = root.attrib.get('to')
			if root.find('from').text:
				sender = root.find('from').text
			else:
				sender = root.attrib.get('from')
			if resiver == options.person or sender == options.person:
				if options.output_dir:
					os.replace(str(os.path.join(ETS_dir, os.path.basename(email))), str(os.path.join(ETS_dir, os.path.basename(email))))
				else:
					output_result(email + '\n', options, default='repr')
			else:
				os.remove(str(os.path.join(ETS_dir, os.path.basename(email))))
	os.rmdir(ETS_dir)


def find_emails_with_definite_time_of_receipt_interval(options):
	if options.start_time_of_receipt == None:
		exit('не задан параметр --start_date')
	if options.end_time_of_receipt == None:
		exit('не задан параметр --end_date')
	
	ETS_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), f'emails_to_sort_{os.getpid()}')
	os.mkdir(ETS_dir)
	
	opt_with_changed_dir = options
	opt_with_changed_dir.output_dir = ETS_dir
	extract_emails(opt_with_changed_dir)
	
	for email in ETS_dir:
		
		tree = ET.parse('email.xml')
		root = tree.getroot()
		
		if datetime.fromisoformat(root.find('DateTimeReceived').text):
			time_of_receipt = datetime.fromisoformat(root.find('DateTimeReceived').text)
		elif datetime.fromisoformat(root.find('DateReceived').text):
			time_of_receipt = datetime.fromisoformat(root.find('DateReceived').text)
		elif datetime.fromisoformat(root.find('.//date').text):
			time_of_receipt = datetime.fromisoformat(root.find('.//date').text)
		else:
			os.remove(str(os.path.join(ETS_dir, os.path.basename(email))))
			continue
		
		if options.start_time_of_receipt <= time_of_receipt <= options.end_time_of_receipt:
			if options.output_dir:
				os.replace(str(os.path.join(ETS_dir, os.path.basename(email))), str(os.path.join(ETS_dir, os.path.basename(email))))
			else:
				output_result(email + '\n', options, default='repr')
		else:
			os.remove(str(os.path.join(ETS_dir, os.path.basename(email))))
	os.rmdir(ETS_dir)
