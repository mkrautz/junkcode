#!/usr/bin/env python
#
# PublicSuffix.org rule parser
#
# Copyright (C) 2010 Mikkel Krautz <mikkel@krautz.dk>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

'''Prototype parser for the publicsuffix.org list of public suffixes
for domains

DomainNameHelper provides a method `get_registered_domain_part()` that
given a domain extracts the part of the domain that can be registered.
One place where this is useful is for determining which level a domain
should be able to set cookies for.'''

__author__   = 'Mikkel Krautz'
__email__    = 'mikkel@krautz.dk'
__license__  = 'MIT'
__version__  = '0.1'
__status__   = 'Prototype'

__all__ = [ 'DomainNameHelper' ]

# TODO:
#
# - The algorithm expects rules to be 'canonicalized', i.e. lower case, punycode (RFC 3492).
#   We're currently not doing that.
#

class PublicSuffixRule(object):
	'''Helper class for reading Public Suffix List rules.'''
	def __init__(self, str):
		self.exception = str.startswith('!')
		if self.exception:
			self.labels = str[1:].split('.')
		else:
			self.labels = str.split('.')
		self.labels.reverse()
		self.key = self.labels[0]

	def __repr__(self):
		return '<PublicSuffixRule %s, excecption=%i>' % (str(self.labels), self.exception)

class DomainNameHelper(object):
	def _read_rules(self):
		'''Read in all the Public Suffix List rules.'''
		self.rules = []
		f = open('effective_tld_names.dat', 'r')
		while True:
			# "The Public Suffix List consists of a series of lines, seperated by \n".
			s = f.readline()
			# EOF
			if s == '':
				break
			# "Each line which [...] (does not begin) with a comment contains a rule."
			if s.startswith('//'):
				continue
			# "Each line which is not entirely whitespace [...] contains a rule"
			trimmed = s.strip()
			if trimmed == '':
				continue
			self.rules.append(PublicSuffixRule(trimmed))

	def __init__(self):
		self._read_rules()
		self.tldmap = {}
		for r in self.rules:
			if not self.tldmap.has_key(r.key):
				self.tldmap[r.key] = []
			self.tldmap[r.key].append(r)

	def _domain_labels(self, domain):
		'''Split a domain into a reversed list of labels.'''
		# "A domain or rule can be split into a list of labels using the
		# seperator '.' (dot). The separator is not part of any of the labels.
		labels = domain.split('.')
		labels.reverse()
		return labels

	def _get_matching_rules(self, domain):
		'''Get a list of matching rules (according to the publicsuffix.org algorithm).'''
		labels = self._domain_labels(domain)
		# No rules for this TLD. "If no rules match, the prevailing rule is '*'."
		if not self.tldmap.has_key(labels[0]):
			return []
		rules = self.tldmap[labels[0]]
		matches = []
		for rule in rules:
			for i, label in enumerate(rule.labels):
				if label == '*':
					continue
				elif label == labels[i]:
					continue
				else:
					break
			else:
				matches.append(rule)
		return matches

	def _get_matching_rule(self, domain):
		'''Get the prevailing rule for a domain.'''
		rules = self._get_matching_rules(domain)
		# If no rules match, the prevailing rule is '*'.
		if len(rules) == 0:
			labels = self._domain_labels(domain)
			return PublicSuffixRule(labels[0])
		# If more than one rule matches, the prevailing rule is
		# the one which is an exception rule.
		exceptions = [ r for r in rules if r.exception ]
		if len(exceptions) > 0:
			rules = exceptions
		# If there is no matching exception rule, the prevailing
		# rule is the one with the most labels.
		mostlabels = None
		for rule in rules:
			if mostlabels is None:
				mostlabels = rule
				continue
			assert(len(mostlabels.labels) != len(rule.labels))
			if len(mostlabels.labels) < len(rule.labels):
				mostlabels = rule
				continue
		if mostlabels:
			return mostlabels

	def get_registered_domain_part(self, domain):
		'''Get the registered domain part of a domain (i.e. the part
		   for which it is safe to set a cookie, amongst other things).'''
		rule = self._get_matching_rule(domain)
		rule_labels = list(rule.labels)
		# If the prevailing rule is an exception rule, modify it by
		# removing the leftmost label.
		if rule.exception:
			rule_labels.pop()
		labels = self._domain_labels(domain)
		parts = []
		for i, label in enumerate(labels):
			if i == len(rule_labels):
				parts.append(label)
				break
			if rule_labels[i] == '*' or rule_labels[i] == label:
				parts.append(label)
				continue
			assert(False)
			break
		# The registered domain is the public suffix plus one additional label.
		if len(parts) < len(rule_labels)+1:
			return None
		parts.reverse()
		return '.'.join(parts)


def test(cls, d1, d2, result=True):
	part = cls.get_registered_domain_part(d1)
	print part
	val = part == d2
	assert(val == result)

if __name__ == '__main__':
	dnh = DomainNameHelper()

	# .com
	test(dnh, 'sub3.sub2.sub1.com', 'sub1.com', True)

	# Matches *.uk rule 
	test(dnh, 'subdomain.bbc.co.uk', 'bbc.co.uk')
	test(dnh, 'co.uk', None)

	# Matches an exception rule (!metro.tokyo.jp)
	test(dnh, 'metro.tokyo.jp', 'metro.tokyo.jp')
	test(dnh, 'sub1.metro.tokyo.jp', 'metro.tokyo.jp')

	# Matches *.ishikawa.jp
	test(dnh, 'registered.somewhere.ishikawa.jp', 'registered.somewhere.ishikawa.jp')

	# Check if our "if not rules match, the prevailing rule is '*'" matching works.
	test(dnh, 'humzzaaa.nonexisting', 'humzzaaa.nonexisting')
