########################################################################
#  Created 2016 based on code Copyright (C) 2013 Sol Birnbaum
# 
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA  02110-1301, USA.
########################################################################

from ..utils.wapxml import wapxmltree, wapxmlnode
from xml.etree import ElementTree as ET

class Search:
    """https://msdn.microsoft.com/en-us/library/gg675482(v=exchg.80).aspx

    Currently for DocumentLibrary searches only.
    """

    # In GAL mode unc_path used to pass search_pattern

    @staticmethod
    def build(unc_path, return_range='0-999', username=None, password=None, mode=None):

        xmldoc_req = wapxmltree()
        xmlrootnode = wapxmlnode("Search")
        xmldoc_req.set_root(xmlrootnode, "search")

        store_node = wapxmlnode("Store", xmlrootnode)

        # "GAL" to search the Global Address List.
        # "Mailbox" to search the mailbox.
        # "DocumentLibrary" to search a Windows SharePoint Services library or a UNC library.
        
        if mode is None:
            name_node = wapxmlnode("Name", store_node, "DocumentLibrary")

            query_node = wapxmlnode("Query", store_node)
            equal_to_node = wapxmlnode("EqualTo", query_node)
            link_id = wapxmlnode("documentlibrary:LinkId", equal_to_node)
            value_node = wapxmlnode("Value", equal_to_node, unc_path)

            options_node = wapxmlnode("Options", store_node)
            range_node = wapxmlnode("Range", options_node, return_range)

            if username is not None:
                username_node = wapxmlnode("UserName", options_node, username)
            if password is not None:
                password_node = wapxmlnode("Password", options_node, password)
        
        elif mode == "GAL":
            name_node = wapxmlnode("Name", store_node, "GAL")
            
            query_node = wapxmlnode("Query", store_node, unc_path)

            options_node = wapxmlnode("Options", store_node)
            range_node = wapxmlnode("Range", options_node, return_range)

            if username is not None:
                username_node = wapxmlnode("UserName", options_node, username)
            if password is not None:
                password_node = wapxmlnode("Password", options_node, password)
        
        else:
            #Implement Mailbox mode, if needed
            pass

        return xmldoc_req

    @staticmethod
    def parse(wapxml):

        namespace = "search"
        root_tag = "Search"

        root_element = wapxml.get_root()
        if root_element.get_xmlns() != namespace:
            raise AttributeError("Xmlns '%s' submitted to '%s' parser. Should be '%s'." % (root_element.get_xmlns(), root_tag, namespace))
        if root_element.tag != root_tag:
            raise AttributeError("Root tag '%s' submitted to '%s' parser. Should be '%s'." % (root_element.tag, root_tag, root_tag))

        children = root_element.get_children()

        status = None
        results = []

        for element in children:
            if element.tag is "Status":
                status = element.text
                if status != "1":
                    print "%s Exception: %s" % (root_tag, status)
            elif element.tag == "Response":

                properties = element.basic_xpath('Store/Result/Properties')
                for properties_el in properties:
                    result = {}
                    properties_children = properties_el.get_children()
                    for prop_el in properties_children:
                        prop = prop_el.tag.partition(':')[2]
                        result[prop] = prop_el.text
                    results.append(result)

        return status, results

# Parse ActiveSync to find emails by keywords
class SearchCommand(object):
    
    def __init__(self, keywords=None, folder_id="inbox"):
        self.keywords = keywords or []
        self.folder_id = folder_id
        self.max_results = max_results
    
    # Construct ActiveSync request XMl
    def build_xml(self):
        root = ET.Element("Search")
        ET.SubElement(root, "Store")
        
        mail_store = ET.SubElement(root.find("Store"), "Mail")
        ET.SubElement(mail_store, "Name").text = "Mailbox"
        
        query = ET.SubElement(mail_store, "Query")
        
        if self.keywords:
            and_element = ET.SubElement(query, "And")
            for keyword in self.keywords:
                or_element = ET.SubElement(and_element, "Or")
                ET.SubElement(or_element, "Subject").text = "*{0}*".format(keyword)
                ET.SubElement(or_element, "Body").text = "*{0}*".format(keyword)
        
        options = ET.SubElement(mail_store, "Options")
        ET.SubElement(options, "Range").text = "0-{0}".format(self.max_results-1)
        
        return ET.tostring(root, encoding="utf-8")
    
    # Parce ActiveSync responce XML
    def parse_response(self, xml_response):
        root = ET.fromstring(xml_response)
        results = []
        
        for response in root.findall(".//{*}Results/{*}Properties"):
            email = {}
            for prop in response:
                tag = prop.tag.split("}")[-1] if "}" in prop.tag else prop.tag
                email[tag] = prop.text
            results.append(email)
        
        return results
