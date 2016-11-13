#!/usr/bin/env python

import ply.lex as lex
import ply.yacc as yacc


t_ignore = ' \t\r\f\v'
t_ignore_comment = r'\#.*|//.*'

def t_newline(t):
	r'\n+'
	t.lexer.lineno += len(t.value)

reserved = {
	'options' : 'OPTIONS',
	'allow-query' : 'ALLOW_QUERY',
	'allow-transfer' : 'ALLOW_TRANSFER',
	'allow-recursion' : 'ALLOW_RECURSION',
	'directory' : 'DIRECTORY',
	'any' : 'ANY',
	'none' : 'NONE',

	'zone' : 'ZONE',
	'type' : 'TYPE',
	'master' : 'MASTER',
	'slave' : 'SLAVE',
	'file' : 'FILE',
	'also-notify' : 'ALSO_NOTIFY',
	'masters' : 'MASTERS',
	'acl' : 'ACL',
	'view' : 'VIEW',
	'match-clients' : 'MATCH_CLIENTS',
	'match-destinations' : 'MATCH_DESTINATIONS',
	'match-recursive-only' : 'MATCH_RECURSIVE_ONLY',
	'yes' : 'YES',
	'no' : 'NO'
}

tokens = [
        'SEMICOLON',
        'LBRACE',
        'RBRACE',
	'DOUBLEQUOTE',
        'IPADDR',
        'IPSPEC',
        'DOMAIN',
        'FILENAME',
	'ID',
] + reserved.values()

states = [
	('zone', 'exclusive'),
	('file', 'exclusive'),
	('directory', 'exclusive')
]


t_SEMICOLON = r';'
t_LBRACE = r'\{'
t_RBRACE = r'\}'
t_DOUBLEQUOTE = r'\"'

def t_error(t):
	raise SyntaxError, "Line %d: Illegal character '%s'" % (t.lexer.lineno, t.value[0])

t_zone_error = t_error
t_file_error = t_error
t_directory_error = t_error

def t_IPSPEC(t):
	r'\d+\.\d+\.\d+\.\d+/\d+|[0-9a-fA-F\:]+\:+[0-9a-fA-F\:]*/\d+'
	return t

def t_IPADDR(t):
	r'\d+\.\d+\.\d+\.\d+|[0-9a-fA-F\:]+\:+[0-9a-fA-F\:]*'
	return t

t_zone_ignore = t_ignore
t_zone_newline = t_newline
#t_zone_DOUBLEQUOTE = t_DOUBLEQUOTE
def t_zone_DOMAIN(t):
	r'\"[a-zA-Z0-9_\-\.]+\"'
	t.value = t.value.strip('"')
	if t.value[-1] != '.':
		t.value = t.value + '.'
	t.value = t.value.lower()
	return t

def t_zone_LBRACE(t):
	r'\{'
	t.lexer.pop_state()
	return t

t_file_ignore = t_ignore
t_file_newline = t_newline
#t_file_DOUBLEQUOTE = t_DOUBLEQUOTE
def t_file_FILENAME(t):
	r'\".+\"'
	t.value = t.value.strip('"')
	return t

def t_file_SEMICOLON(t):
	r';'
	t.lexer.pop_state()
	return t

t_directory_ignore = t_ignore
t_directory_newline = t_newline
def t_directory_FILENAME(t):
	r'\".+\"'
	t.value = t.value.strip('"')
	return t

def t_directory_SEMICOLON(t):
	r';'
	t.lexer.pop_state()
	return t


def t_ID(t):
        r'[a-zA-Z][a-zA-Z_0-9\-]*'
        t.type = reserved.get(t.value,'ID')
	if t.type == 'ZONE':
		t.lexer.push_state('zone')
	if t.type == 'FILE':
		t.lexer.push_state('file')
	if t.type == 'DIRECTORY':
		 t.lexer.push_state('directory')
        return t

lex.lex()

#### 

class Conf:
	def __init__(self, statements, pos):
		self.acl = {}
		self.options = Options([], (0,0))
		self.zones = []
		self.views = []
		for i in statements:
			if isinstance(i, Options):
				self.options = i
			elif isinstance(i, ZoneMaster):
				self.zones.append(i)
			elif isinstance(i, ZoneSlave):
				self.zones.append(i)
			elif isinstance(i, Acl):
				self.acl[i.name] = i.list
			elif isinstance(i, View):
				self.views.append(i)

	def __repr__(self):
		s = 'Conf(\n'
		s = s + (" Acl(%s\n)" % self.acl)
		s += ' %s,' % self.options 
		for i in self.zones:
			s = s + (" %s\n" % i)
		for i in self.views:
			s = s + (" %s\n" % i)
		s += ')\n'
		return s

	def check(self):
		self.options.check()
		zones = []
		for i in self.zones:
			if i.name in zones:
				raise SyntaxError, 'Line %d: duplicate zone "%s"' % (i.pos[0], i.name)
			zones.append(i.name)
			i.check()
		self.process_view()
		self.resolvacl()

	def resolvacl(self):
		# first resolve aclid in acls
		for i in range(5):
			for k in self.acl.keys():
				self.acl[k] = aclidtoip(self.acl, self.acl[k])
		# check if all aclids are resolved
		try:
			for k in self.acl.keys():
				aclidtoip({}, self.acl[k])
		except SyntaxError as e:
			raise SyntaxError, '%s: too deep or cyclic acl id reference detected' % e.args
		for v in self.views:
			v.allow_query = aclidtoip(self.acl, v.allow_query)
			aclidtoip({}, v.allow_query)
			v.allow_recursion = aclidtoip(self.acl, v.allow_recursion)
			aclidtoip({}, v.allow_recursion)
			v.allow_transfer = aclidtoip(self.acl, v.allow_transfer)
			aclidtoip({}, v.allow_transfer)
			v.match_clients = aclidtoip(self.acl, v.match_clients)
			aclidtoip({}, v.match_clients) 
			for z in v.zones:
				z.allow_transfer = aclidtoip(self.acl, z.allow_transfer)
	def process_view(self):
		# create default view
		v = View('_default', [], (0,0))
		v.allow_recursion = self.options.allow_recursion
		v.allow_query = self.options.allow_query
		v.allow_transfer =  self.options.allow_transfer
		v.zones = self.zones
		self.views.append(v)
		for v in self.views:
			if v.allow_query == None:
				v.allow_query = self.options.allow_query
			if v.allow_recursion == None:
				v.allow_recursion = self.options.allow_recursion
			if v.allow_transfer == None:
				v.allow_transfer = self.options.allow_transfer
			for z in v.zones:
				if z.allow_transfer == None:
					z.allow_transfer = v.allow_transfer

def aclidtoip(acl, list):
	newa = []
	for i in list:
		if isinstance(i, AclId):
			ip = acl.get(i.name, None)
			if ip == None:
				raise SyntaxError, 'Line %d: unknown acl %s' % (i.pos[0], i.name)
			else:
				newa += ip
		else:
			newa.append(i)
	return newa

class Options:
	def __init__(self, option_clause, pos):
		self.allow_recursion = []
		self.allow_query = ['0.0.0.0/0', '::0/0']
		self.allow_transfer = []
		self.directory = None
		self.also_notify = None
		for i in option_clause:
			if isinstance(i, Directory):
				self.directory = i.tostr()
			elif isinstance(i, AllowTransfer):
				self.allow_transfer = i.tolist()
			elif isinstance(i, AllowRecursion):
				self.allow_recursion = i.tolist()
			elif isinstance(i, AllowQuery):
				self.allow_query = i.tolist()
			elif isinstance(i, AlsoNotify):
				self.also_notify = i.tolist()

	def __repr__(self):
		s =  'Options(\n'
		s += ' allow_query=%s,\n' % self.allow_query
		s += ' allow_transfer=%s\n' % self.allow_transfer
		s += ' allow_recursion=%s\n' % self.allow_recursion
		s += ' directory="%s")\n' % self.directory
		return s
	def check(self):
		pass

class ZoneMaster:
	def __init__(self, name, zone_clause, pos):
		self.name = name
		self.allow_transfer = None
		self.file = None
		self.also_notify = None
		self.pos = pos
		for i in zone_clause:
			if isinstance(i, AllowTransfer):
				self.allow_transfer = i.tolist()
			elif isinstance(i, File):
				self.file = i.name
			elif isinstance(i, AlsoNotify):
				self.also_notify = i.tolist()

	def __repr__(self):
		return 'ZoneMaster("%s", file="%s", allow_transfer=%s, also-notify=%s)' % (self.name, self.file, self.allow_transfer, self.also_notify)

	def check(self):
		if not self.file:
			raise SyntaxError, 'Line %d: master zone "%s" requires "file" clause' % (self.pos[0], self.name)


class File:
	def __init__(self, name):
		self.name = name

class ZoneSlave:
	def __init__(self, name, zone_clause, pos):
		self.name = name
		self.allow_transfer = None
		self.masters = None
		self.also_notify = None
		self.pos = pos
		for i in zone_clause:
			if isinstance(i, AllowTransfer):
				self.allow_transfer = i.tolist()
			elif isinstance(i, Masters):
				self.masters = i.tolist()
			elif isinstance(i, AlsoNotify):
				self.also_notify = i.tolist()

	def __repr__(self):
		return 'ZoneSlave("%s", masters=%s, allow_transfer=%s)' % (self.name, self.masters, self.allow_transfer)
	def check(self):
		if not self.masters:
			raise SyntaxError, 'Line %d: slave zone "%s" requires "masters" clause' % (self.pos[0], self.name)
	def check(self):
		if not self.masters:
			raise SyntaxError, 'Line %d: slave zone "%s" requires "masters" clause' % (self.pos[0], self.name)

class Acl:
	def __init__(self, name, iplist, pos):
		self.name = name
		self.list = iplist
		self.pos = pos
	def __repr__(self):
		return 'Acl("%s", %s)' % ( self.name, self.list)

class AclId:
	def __init__(self, name, pos):
		self.name = name
		self.pos = pos
	def __repr__(self):
		return 'AclId("%s")' % self.name

class Directory:
	def __init__(self, name):
		self.name = name
	def tostr(self):
		return self.name
	def __repr__(self):
		return name

class AllowList:
	def __init__(self, allowlist):
		self.allowlist = allowlist
	def tolist(self):
		return self.allowlist

class IPList:
	def __init__(self, iplist):
		self.iplist = iplist
	def tolist(self):
		return self.iplist

class Masters(IPList):
	pass

class AlsoNotify(IPList):
	pass

class AllowTransfer(AllowList):
	pass

class AllowRecursion(AllowList):
	pass

class AllowQuery(AllowList):
	pass

class MatchClients(AllowList):
	pass

class MatchDestinations(AllowList):
	pass

class MatchRecursiveOnly:
	def __init__(self, yesno):
		self.yesno = yesno

class View():
	def __init__(self, name, view_clause, pos):
		self.allow_recursion = None
		self.allow_query = None
		self.allow_transfer = None
		self.also_notify = None
		self.zones = []
		self.match_clients = [ '0.0.0.0/0', '::0/0' ]
		self.match_destinations = [ '0.0.0.0/0', '::0/0' ]
		self.match_recursive_only = False
		self.name = name
		for i in view_clause:
			if isinstance(i, AllowTransfer):
				self.allow_transfer = i.tolist()
			elif isinstance(i, AllowRecursion):
				self.allow_recursion = i.tolist()
			elif isinstance(i, AllowQuery):
				self.allow_query = i.tolist()
			elif isinstance(i, ZoneMaster):
				self.zones.append(i)
			elif isinstance(i, ZoneSlave):
				self.zones.append(i)
			elif isinstance(i, MatchClients):
				self.match_clients = i.allowlist
			elif isinstance(i, MatchDestinations):
				self.match_destinations = i.allowlist
			elif isinstance(i, MatchRecursiveOnly):
				self.match_recursive_only = i.yesno
	def __repr__(self):
		s = 'View(name="%s",\n' % self.name
		s += '  allow_recursion=%s\n' % self.allow_recursion
		s += '  allow_query=%s\n' % self.allow_query
		s += '  allow_transfer=%s\n' % self.allow_transfer
		s += '  match_clients=%s\n' % self.match_clients
		s += '  match_destinations=%s\n' % self.match_destinations
		s += '  match_recursive_only=%s\n' % self.match_recursive_only
		s += '  zones=%s\n)\n' % self.zones
		return s


		


def p_error(token):
	if token is not None:
		raise SyntaxError, "Line %s, illegal token %s" % (token.lineno, token.value)
	else:
		raise SyntaxError, 'Unexpected end of input'

def p_conf(p):
	'conf : statements'
	p[0] = Conf(p[1], (p.lineno(1), p.lexpos(1)))

def p_statements(p):
	'''statements : statements statement
		| statement'''
	if len(p) == 3:
		p[0] = p[1] + [p[2]]
	else:
		p[0] = [p[1]]

def p_statement(p):
	'''statement : statement_options
		| statement_zone_master
		| statement_zone_slave
		| statement_view
		| statement_acl'''
	p[0] = p[1]

def p_statement_options(p):
	'statement_options : OPTIONS LBRACE block_options RBRACE SEMICOLON'
	# list of AllowTransfer, AllowQuery, AllowRecursion, Directory
	p[0] = Options(p[3], (p.lineno(1), p.lexpos(1)))

def p_block_options(p):
	'''block_options : block_options clause_options
		| clause_options'''
	if len(p) == 3:
		p[0] = p[1] + [p[2]]
        else:
		p[0] = [p[1]]

def p_clause_options(p):
	'''clause_options : allow_query
		| allow_transfer
		| allow_recursion
		| directory'''
	p[0] = p[1]

def p_clause_directory(p):
	'directory : DIRECTORY FILENAME SEMICOLON'
	p[0] = Directory(p[2])

def p_statement_zone_master(p):
	'statement_zone_master : ZONE DOMAIN LBRACE TYPE MASTER SEMICOLON block_zone_master RBRACE SEMICOLON'
	p[0] = ZoneMaster(p[2], p[7] , (p.lineno(1), p.lexpos(1)))

def p_statement_zone_slave(p):
	'statement_zone_slave : ZONE DOMAIN LBRACE TYPE SLAVE SEMICOLON block_zone_slave RBRACE SEMICOLON'
	p[0] = ZoneSlave(p[2], p[7], (p.lineno(1), p.lexpos(1)))

def p_statement_view(p):
	'statement_view : VIEW ID LBRACE block_view RBRACE SEMICOLON'
	p[0] = View(p[2], p[4], (p.lineno(1), p.lexpos(1)))

def p_statements_view(p):
	'''block_view : block_view clause_view
		| clause_view'''
	if len(p) == 3:
		p[0] = p[1] + [p[2]]
	else:
		p[0] = [p[1]]

def p_clause_view(p):
	'''clause_view : allow_transfer
		| allow_query
		| allow_recursion
		| match_clients
		| match_destinations
		| match_recursive_only
		| statement_zone_slave
		| statement_zone_master'''
	p[0] = p[1]

def p_block_zone_master(p):
	'''block_zone_master : block_zone_master clause_zone_master
		| clause_zone_master'''
	if len(p) == 3:
		p[0] = p[1] + [p[2]]
	else:
		p[0] = [p[1]]

def p_block_zone_slave(p):
	'''block_zone_slave : block_zone_slave clause_zone_slave
		| clause_zone_slave'''
	if len(p) == 3:
		p[0] = p[1] + [p[2]]
	else:
		p[0] = [p[1]]

def p_clause_zone_master1(p):
	'clause_zone_master : FILE FILENAME SEMICOLON'
	p[0] = File(p[2])

def p_clause_zone_master2(p):
	'clause_zone_master : allow_transfer'
	p[0] = p[1]

def p_clause_zone_master3(p):
	'clause_zone_master : ALSO_NOTIFY LBRACE ip_list RBRACE SEMICOLON'
	p[0] = AlsoNotify(p[3])

def p_clause_zone_slave1(p):
	'clause_zone_slave : MASTERS LBRACE ip_list RBRACE SEMICOLON'
	p[0] = Masters(p[3])

def p_clause_zone_slave2(p):
	'clause_zone_slave : allow_transfer'
	p[0] = p[1]

def p_clause_zone_slave3(p):
	'clause_zone_slave : ALSO_NOTIFY LBRACE ip_list RBRACE SEMICOLON'
	p[0] = Masters(p[3])

def p_statement_acl(p):
	'''statement_acl : ACL ID LBRACE ipspec_list RBRACE SEMICOLON
			| ACL DOUBLEQUOTE ID DOUBLEQUOTE LBRACE ipspec_list RBRACE SEMICOLON'''
	if len(p) == 7:
		p[0] = Acl(p[2], p[4], (p.lineno(1), p.lexpos(1)))
	else:
		p[0] = Acl(p[3], p[6], (p.lineno(1), p.lexpos(1)))

def p_clause_allow_query(p):
	'allow_query : ALLOW_QUERY LBRACE ipspec_list RBRACE SEMICOLON'
	p[0] = AllowQuery(p[3])

def p_clause_allow_transfer(p):
	'allow_transfer : ALLOW_TRANSFER LBRACE ipspec_list RBRACE SEMICOLON'
	p[0] = AllowTransfer(p[3])

def p_clause_allow_recursion(p):
	'allow_recursion : ALLOW_RECURSION LBRACE ipspec_list RBRACE SEMICOLON'
	p[0] = AllowRecursion(p[3])

def p_clause_match_clients(p):
	'match_clients : MATCH_CLIENTS LBRACE ipspec_list RBRACE SEMICOLON'
	p[0] = MatchClients(p[3])

def p_clause_match_destination(p):
	'match_destinations : MATCH_DESTINATIONS LBRACE ipspec_list RBRACE SEMICOLON'
	p[0] = MatchDestinations(p[3])

def p_clause_match_recursive_only_yes(p):
	'match_recursive_only : MATCH_RECURSIVE_ONLY YES SEMICOLON'
	p[0] = MatchRecursiveOnly(True)

def p_clause_match_recursive_only_no(p):
	'match_recursive_only : MATCH_RECURSIVE_ONLY NO SEMICOLON'
	p[0] = MatchRecursiveOnly(False)

def p_ipspec_list1(p):
	'''ipspec_list : NONE SEMICOLON
		| ANY SEMICOLON
		| ipspec_list IPSPEC SEMICOLON
		| ipspec_list IPADDR SEMICOLON
		| IPADDR SEMICOLON
		| IPSPEC SEMICOLON'''
	if len(p) == 3:
		if p[1] == 'none':
			p[0] = []
		elif p[1] == 'any':
			p[0] = ['0.0.0.0/0', '::/0']
		else:
			p[0] = [p[1]]
	else:
		p[0] = p[1] + [p[2]]


def p_ipspec_list2(p):
	'''ipspec_list : ipspec_list ID SEMICOLON
		| ID SEMICOLON'''
	if len(p) == 3:
		p[0] = [AclId(p[1], (p.lineno(2), p.lexpos(2)))]
	else:
		p[0] = p[1] + [AclId(p[2], (p.lineno(2), p.lexpos(2)))]

def p_ip_list(p):
	'''ip_list : IPADDR SEMICOLON
		| ip_list IPADDR SEMICOLON'''
	if len(p) == 3:
		p[0] = [p[1]]
	else:
		p[0] = p[1] + [p[2]]


yacc.yacc(write_tables=False, debug=False)

ddtempl = '''
function xfr_query_%s(dq)
        if(dq.qtype == dnsdist.AXFR or dq.qtype == dnsdist.IXFR)
        then
                a = %s[string.lower(dq.qname:toString())]
                if(%s:match(dq.remoteaddr) and a:match(dq.remoteaddr))
                then
                	return DNSAction.Pool, "%s"
		end
        end
        return DNSAction.None, ""
end
'''

def dnsdist(conf, localaddr=["0.0.0.0:53", "[::]:53"],
	port_base=40000):
	authport = port_base
	resolverport = port_base + 1
	confline = ""

	for v in conf.views:
		confline += '\n\n'
		confline += '-- view "%s"\n\n' % v.name
		auth = 'auth_' + v.name
		resolver = 'resolver_' + v.name
		authaddr = '127.0.0.1:%d' % authport
		resolveraddr = '127.0.0.1:%d' % resolverport
	
		confline += 'newServer({address="%s", pool="%s"})\n' % (authaddr, auth)
		confline += 'newServer({address="%s", pool="%s"})\n' % (resolveraddr, resolver)
		confline += 'pc = newPacketCache(100000)\n'
		confline += 'getPool("%s"):setCache(pc)\n' % resolver
		confline += '\n'
		match_clients = 'match_clients_' + v.name
		match_destinations = 'match_destinations_' + v.name
		match_recursive_only = 'match_recursive_only_' + v.name
		allow_query = 'allow_query_' + v.name
		allow_recursion = 'allow_recursion_' + v.name
		allow_transfer = 'allow_transfer_' + v.name
		authdomains = 'authdomains_' + v.name

		confline +='%s = newNMG()\n' % match_clients
		for a in v.match_clients:
			confline +='%s:addMask("%s")\n' % (match_clients, a)
		confline +='%s = newNMG()\n' % match_destinations
		for a in v.match_destinations:
			confline +='%s:addMask("%s")\n' % (match_destinations, a)
		confline += '%s = newNMG()\n' % allow_query
		for a in v.allow_query:
			confline += '%s:addMask("%s")\n' % (allow_query, a)

		confline += '%s = newNMG()\n' % allow_recursion
		for a in v.allow_recursion:
			confline += '%s:addMask("%s")\n' % (allow_recursion, a)

		confline += '%s = newSuffixMatchNode()\n' % authdomains
		confline += '%s = {}\n' % allow_transfer

		for z in v.zones:
			confline += '%s:add(newDNSName("%s"))\n' % (authdomains, z.name)
			confline += '%s["%s"] = newNMG()\n' % (allow_transfer, z.name)
			for a in z.allow_transfer:
				confline += '%s["%s"]:addMask("%s")\n' % (allow_transfer, z.name, a)

		confline += '\n'
		confline += ddtempl % (v.name, allow_transfer, match_clients, auth)
		confline += '\n'

		if v.name == '_default':
			confline += 'addAction(AndRule({NotRule(NetmaskGroupRule(%s))}), RCodeAction(5))\n' % allow_query
			confline += 'addAction(AndRule({NotRule(QTypeRule(dnsdist.AXFR)), NotRule(QTypeRule(dnsdist.IXFR)), SuffixMatchNodeRule(%s)}), PoolAction("%s"))\n' % (authdomains, auth)
			confline += 'addAction(AndRule({NotRule(QTypeRule(dnsdist.AXFR)), NotRule(QTypeRule(dnsdist.IXFR)), NetmaskGroupRule(%s)}), PoolAction("%s"))\n' % (match_clients, resolver)
		else:
			confline += 'addAction(AndRule({NetmaskGroupRule(%s), NotRule(NetmaskGroupRule(%s))}), RCodeAction(5))\n' % (match_clients, allow_query)
                        confline += 'addAction(AndRule({NetmaskGroupRule(%s), NotRule(QTypeRule(dnsdist.AXFR)), NotRule(QTypeRule(dnsdist.IXFR)), SuffixMatchNodeRule(%s)}), PoolAction("%s"))\n' % (match_clients, authdomains, auth)
                        confline += 'addAction(AndRule({NetmaskGroupRule(%s), NotRule(QTypeRule(dnsdist.AXFR)), NotRule(QTypeRule(dnsdist.IXFR)), NetmaskGroupRule(%s)}), PoolAction("%s"))\n' % (match_clients, allow_recursion, resolver)
		confline += 'addLuaAction(".", xfr_query_%s)\n' % v.name
		confline += 'addAction(NetmaskGroupRule(%s), RCodeAction(5))\n' % match_clients
		authport += 2
		resolverport += 2

	confline += 'addAction(AllRule(), RCodeAction(5))\n\n'
	confline += 'setACL({})\n'
	confline += 'addACL("0.0.0.0/0")\n'
	confline += 'addACL("::0/0")\n'
	confline += 'controlSocket("127.0.0.1")\n\n'
	for l in localaddr:
		confline += 'addLocal("%s")\n' % l
	return confline

def nsd(conf, port_base=40000, port_control_base=41000):
	c = []
	for v in conf.views:
		confline = ""
		confline += 'server:\n'
		if conf.options.directory:
			confline += ' zonesdir: "%s"\n' % conf.options.directory
		confline += ' ip-address: %s@%d\n' % ('127.0.0.1', port_base)

		for z in v.zones:
			confline += 'zone:\n'
			confline += ' name:"%s"\n' % z.name
			if isinstance(z, ZoneMaster):
				confline += ' zonefile: "%s"\n' % z.file
				confline += ' provide-xfr: 127.0.0.1 NOKEY\n'
			elif isinstance(z, ZoneSlave):
				for m in z.masters:
					confline += ' request-xfr: %s NOKEY\n' % m
		confline +='\n'
		if v.name != '_default':
			confline += 'remote-control:\n'
			confline += ' control-port: %d\n' % port_control_base
		c.append((v.name, confline))
		port_base += 2
		port_control_base +=2
	return c


def unbound(conf, port_base=40000, port_control_base=41000):
	c = []
	port_base += 1
	port_control_base += 1
	for v in conf.views:
		confline = ""
		confline += 'server:\n'
		confline += ' interface: %s@%d\n' % ('127.0.0.1', port_base)
		confline += ' access-control: 127.0.0.1 allow\n'
		if v.name != '_default':
			confline += 'remote-control:\n'
			confline += ' control-port: %d\n' % port_control_base
		c.append((v.name, confline))
		port_base +=2
		port_control_base += 2
	return c


import sys

if __name__ == '__main__':
	f = open(sys.argv[1])
	conf = yacc.parse(f.read())
	conf.check()

	f = open('dnsdist.conf', 'w')
	f.write(dnsdist(conf))

	for c in nsd(conf):
		if c[0] == '_default':
			filename = 'nsd.conf'
		else:
			filename = 'nsd_' + c[0] + '.conf'
		f = open(filename, 'w')
		f.write(c[1])

	for c in unbound(conf):
		if c[0] == '_default':
			filename = 'unbound.conf'
		else:
			filename = 'unbound_' + c[0] + '.conf'
		f = open(filename, 'w')
		f.write(c[1])


