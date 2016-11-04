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
#	'notify' : 'NOTIFY',
	'masters' : 'MASTERS',
	'acl' : 'ACL'
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
	r'\d+\.\d+\.\d+\.\d+/\d+|[0-9a-fA-F\:]*\:+[0-9a-fA-F\:]*/\d+'
	return t

def t_IPADDR(t):
	r'\d+\.\d+\.\d+\.\d+|[0-9a-fA-F\:]*\:+[0-9a-fA-F\:]*'
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
        r'[a-zA-Z_][a-zA-Z_0-9\-]*'
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
		for i in statements:
			if isinstance(i, Options):
				self.options = i
			elif isinstance(i, ZoneMaster):
				self.zones.append(i)
			elif isinstance(i, ZoneSlave):
				self.zones.append(i)
			elif isinstance(i, Acl):
				self.acl[i.name] = i.list
	def __repr__(self):
		s = 'Conf(\n'
		s = s + (" Acl(%s\n)" % self.acl)
		s += ' %s,' % self.options 
		for i in self.zones:
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
		# resolve aclid in options.allow_query
		self.options.allow_query = aclidtoip(self.acl, self.options.allow_query)
		# check if all aclids are resolved
		aclidtoip({}, self.options.allow_query)

		self.options.allow_transfer = aclidtoip(self.acl, self.options.allow_transfer)
		aclidtoip({}, self.options.allow_transfer)
		self.options.allow_recursion = aclidtoip(self.acl, self.options.allow_recursion)
		aclidtoip({}, self.options.allow_recursion)

		for z in self.zones:
			if z.allow_transfer:
				z.allow_transfer = aclidtoip(self.acl, z.allow_transfer )
				aclidtoip({}, z.allow_transfer)

def aclidtoip(acl, list):
	newa = []
	for i in list:
		if isinstance(i, AclId):
			ip = acl.get(i.name, None)
			if not ip:
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
		for i in option_clause:
			if isinstance(i, Directory):
				self.directory = i.tostr()
			elif isinstance(i, AllowTransfer):
				self.allow_transfer = i.tolist()
			elif isinstance(i, AllowRecursion):
				self.allow_recursion = i.tolist()
			elif isinstance(i, AllowQuery):
				self.allow_query = i.tolist()

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
		self.pos = pos
		for i in zone_clause:
			if isinstance(i, AllowTransfer):
				self.allow_transfer = i.tolist()
			elif isinstance(i, File):
				self.file = i.name
	def __repr__(self):
		return 'ZoneMaster("%s", file="%s", allow_transfer=%s)' % (self.name, self.file, self.allow_transfer)

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
		self.pos = pos
		for i in zone_clause:
			if isinstance(i, AllowTransfer):
				self.allow_transfer = i.tolist()
			elif isinstance(i, Masters):
				self.masters = i.tolist()
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

class AllowTransfer(AllowList):
	pass

class AllowRecursion(AllowList):
	pass

class AllowQuery(AllowList):
	pass

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

def p_statement_options(p):
	'statement : OPTIONS LBRACE block_options RBRACE SEMICOLON'
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
	'statement : ZONE DOMAIN LBRACE TYPE MASTER SEMICOLON block_zone_master RBRACE SEMICOLON'
	p[0] = ZoneMaster(p[2], p[7] , (p.lineno(1), p.lexpos(1)))

def p_statement_zone_slave(p):
	'statement : ZONE DOMAIN LBRACE TYPE SLAVE SEMICOLON block_zone_slave RBRACE SEMICOLON'
	p[0] = ZoneSlave(p[2], p[7], (p.lineno(1), p.lexpos(1)))

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

def p_clause_zone_slave1(p):
	'clause_zone_slave : MASTERS LBRACE ip_list RBRACE SEMICOLON'
	p[0] = Masters(p[3])

def p_clause_zone_slave2(p):
	'clause_zone_slave : allow_transfer'
	p[0] = p[1]

def p_statement_acl(p):
	'''statement : ACL ID LBRACE ipspec_list RBRACE SEMICOLON
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
pc = newPacketCache(100000)
getPool("resolver"):setCache(pc)

function xfr_query(dq)
        if(dq.qtype == dnsdist.AXFR or dq.qtype == dnsdist.IXFR)
        then
                a = allow_transfer[string.lower(dq.qname:toString())]
		if(not (a))
		then
			a = allow_transfer_global
		end
                if(a:match(dq.remoteaddr))
                then
                	return DNSAction.Pool, "auth"
                end
        end
        return DNSAction.None, ""
end

addAction(NotRule(NetmaskGroupRule(allow_query)),
        RCodeAction(dnsdist.REFUSED))
addAction(AndRule({NotRule(QTypeRule(dnsdist.AXFR)), NotRule(QTypeRule(dnsdist.IXFR)), SuffixMatchNodeRule(authdomains)}), PoolAction("auth"))
addAction(AndRule({NotRule(QTypeRule(dnsdist.AXFR)), NotRule(QTypeRule(dnsdist.IXFR)), NetmaskGroupRule(allow_recursion)}), PoolAction("resolver"))
addLuaAction(".", xfr_query)
addAction(AllRule(), RCodeAction(dnsdist.REFUSED))

setACL({})
addACL("0.0.0.0/0")
addACL("::0/0")
controlSocket("127.0.0.1")
'''

def dnsdist(conf,
	authaddr="127.0.0.1:10053",
	resolveraddr="127.0.0.1:10054",
	localaddr=["0.0.0.0:53", "[::]:53"]):
	
	confline = ""
	confline += 'newServer({address="%s", pool="resolver"})\n' % resolveraddr
	confline += 'newServer({address="%s", pool="auth"})\n' % authaddr

	confline += 'allow_query = newNMG()\n'
	for a in conf.options.allow_query:
		confline += 'allow_query:addMask("%s")\n' % a

	confline += 'allow_recursion = newNMG()\n'
	for a in conf.options.allow_recursion:
		confline += 'allow_recursion:addMask("%s")\n' % a

	confline += 'allow_transfer_global = newNMG()\n'
	for a in conf.options.allow_transfer:
		confline += 'allow_transfer_global:addMask("%s")\n' % a

	confline += 'allow_transfer = {}\n'
	confline += 'authdomains = newSuffixMatchNode()\n'
	for z in conf.zones:
		zone = z.name
		confline += 'authdomains:add(newDNSName("%s"))\n' % zone
		if z.allow_transfer:
			confline += 'allow_transfer["%s"] = newNMG()\n' % zone
			for a in z.allow_transfer:
				confline += 'allow_transfer["%s"]:addMask("%s")\n' % (zone, a)
	for l in localaddr:
		confline += 'addLocal("%s")\n' % l
	return confline + ddtempl

def nsd(conf, authaddr="127.0.0.1:10053"):
	confline = ""
	confline += 'server:\n'
	if conf.options.directory:
		confline += ' zonesdir: "%s"\n' % conf.options.directory
	confline += ' ip-address: %s\n' % authaddr.replace(':', '@')
	#confline += ' username: ""\n'
	#confline += ' chroot: ""\n'

	for z in conf.zones:
		confline += 'zone:\n'
		confline += ' name:"%s"\n' % z.name
		if isinstance(z, ZoneMaster):
			confline += ' zonefile: "%s"\n' % z.file
			confline += ' provide-xfr: 127.0.0.1 NOKEY\n'
		elif isinstance(z, ZoneSlave):
			for m in z.masters:
				confline += ' request-xfr: %s NOKEY\n' % m

	return confline

def unbound(conf, resolveraddr="127.0.0.1:10054"):
	confline = ""
	confline += 'server:\n'
	confline += ' interface: %s\n' % resolveraddr.replace(':', '@')
	confline += ' access-control: 127.0.0.1 allow\n'
	# confline += ' username: ""\n'
	# confline += ' chroot: ""\n'
	return confline

import sys

if __name__ == '__main__':
	f = open(sys.argv[1])
	conf = yacc.parse(f.read())
	conf.check()

	f = open('dnsdist.conf', 'w')
	f.write(dnsdist(conf))

	f = open('nsd.conf', 'w')
	f.write(nsd(conf))

	f = open('unbound.conf', 'w')
	f.write(unbound(conf))

