
import lxml
import lxml.etree
cmd ='''
<zonecommand>
	<commandId>d2c68649-3e95-45b3-8879-e5b0deb91494</commandId>
	<datasources>2</datasources>
	<urgency>2</urgency>
	<range>
		<dnsId>2019041500134400001330002</dnsId>
		<effectiveScope>1</effectiveScope>
		<serverId></serverId>
	</range>
	<privilege>
		<owner>admin</owner>
			<visible>1</visible>
			<check>admin</check>
	</privilege>
	<timeStamp>2019-07-02 17:01:05</timeStamp>
</zonecommand>
'''

def xmlget(root, xpath):
	lst = root.xpath(xpath)
	if lst and lst[0].text:
		return lst[0].text

	return None

ele = lxml.etree.fromstring(cmd)
_commandId = xmlget(ele, 'commandId')
print(_commandId)
_type = xmlget(ele, 'type')
print(_type)
_urgency = xmlget(ele, 'urgency')
if _urgency == '2':
	print(2222)
print(_urgency)
_effectiveScope = xmlget(ele, 'range/effectiveScope')
print(_effectiveScope)
_check = xmlget(ele, 'privilege/check')
print(_check)
_timestamp = xmlget(ele, 'timeStamp')
print(_timestamp)
_datasources = int(xmlget(ele, 'datasources'))
print(_datasources)




