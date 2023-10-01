import random

from DaNuoYi.injection_utils.payload.payload_dict import PayloadDict


class Payload(object):

    def __init__(self, dict_type, tag=None, cld=None, length=0, auto=True):
        self.ctx = list()
        self.ctx.append(tag)
        self.injection = ''
        self.cld = cld
        self.tag = tag

        self.length = length
        self.sub_ctx = None
        self.target = None
        self.i = 1

        if auto:
            if dict_type.upper() == 'XSS':
                self.generate_ctx('root', PayloadDict().ebnfXSS)
                self.payload_dict = PayloadDict().ebnfXSS
            elif dict_type.upper() == 'SQLI':
                self.generate_ctx('root', PayloadDict().ebnfSQLi)
                self.payload_dict = PayloadDict().ebnfSQLi
            elif dict_type.upper() == 'PHPI':
                self.generate_ctx('root', PayloadDict().ebnfPHPi)
                self.payload_dict = PayloadDict().ebnfPHPi
            elif dict_type.upper() == 'OSI':
                self.generate_ctx('root', PayloadDict().ebnfOSi)
                self.payload_dict = PayloadDict().ebnfOSi
            elif dict_type.upper() == 'XMLI':
                self.generate_ctx('root', PayloadDict().ebnfXMLi)
                self.payload_dict = PayloadDict().ebnfXMLi
            elif dict_type.upper() == 'HTMLI':
                self.generate_ctx('root', PayloadDict().ebnfHTMLi)
                self.payload_dict = PayloadDict().ebnfHTMLi
            else:
                print('Error injection task name!')
            self.injection = self.generate_str(self.ctx)
        else:
            self.payload_dict = dict_type

    def generate_ctx(self, tag, dictory):
        if tag not in dictory.keys():
            return tag
        sub_table = dictory[tag]
        cld = random.choice(sub_table) if len(sub_table) > 1 else sub_table[0]
        children = dict(tag=tag, cld=cld, ctx=list())
        children['ctx'].append(tag)

        for child in children['cld']:
            temp = self.generate_ctx(child, dictory)[:]
            children['ctx'].append(temp)
        self.ctx = children['ctx']
        self.length += 1
        return children['ctx']

    def traversal(self, ctx):
        res = list()
        for i in ctx:
            if isinstance(i, list):
                res.extend(self.traversal(ctx=i[1:]))
            else:
                res.append(i + ' ')
        return res

    def generate_str(self, ctx):
        return ''.join(self.traversal(ctx)[1:])

    def get_tag_slice(self, ctx, tag):
        res = list()
        for i in range(len(ctx)):
            if isinstance(ctx[i], list):
                if ctx[i][0] == tag:
                    res.append(ctx[i])
                else:
                    res.extend(self.get_tag_slice(ctx[i][1:], tag))
        return res

    def get_index_slice(self, ctx, index=999, begin=True):
        if begin:
            self.i = 1
        for j in ctx:
            if isinstance(j, list):
                self.i += 1
                if self.i > index:
                    self.target = j[0]
                    self.sub_ctx = j
                else:
                    self.get_index_slice(j[1:], index, False)
        return self.target, self.sub_ctx

    def set_slice(self, option_slice, option, slices):
        try:
            # same tag
            if option_slice[option][0] == slices[0]:
                option_slice[option][1:] = slices[1:]
            if option_slice[0] == slices[option][0]:
                option_slice[1:] = slices[option][1:]
            if option_slice[0] == slices[0]:
                option_slice[1:] = slices[1:]
        except Exception as e:
            print('Index overstep: %s' % IndexError)

    def grammar_characteristics(self):
        """
        Calculate the characteristics of the grammar
        :return: A dictionary containing grammar characteristics
        """
        num_productions = len([x for x in self.payload_dict if self.is_productive(x, set())])
        num_terminals = len([y for x in self.payload_dict for y in self.payload_dict[x] if self.is_terminal(y)])
        num_nonterminals = len([x for x in self.payload_dict if not self.is_terminal(x)])
        num_recursive_productions = len([x for x in self.payload_dict if self.is_recursive(x, set())])
        num_unproductive_symbols = len([x for x in self.payload_dict if self.is_non_productive(x, set())])
        num_inaccessible_symbols = len([x for x in self.payload_dict if not self.is_accessible(x, 'root', set())])

        print("Number of Productions: %d" % num_productions)
        print("Number of Terminals: %d" % num_terminals)
        print("Number of Nonterminals: %d" % num_nonterminals)
        print("Number of Recursive Productions: %d" % num_recursive_productions)
        print("Number of Unproductive Symbols: %d" % num_unproductive_symbols)
        print("Number of Inaccessible Symbols: %d" % num_inaccessible_symbols)

        return {
            "Number of Productions": num_productions,
            "Number of Terminals": num_terminals,
            "Number of Nonterminals": num_nonterminals,
            "Number of Recursive Productions": num_recursive_productions,
            "Number of Unproductive Symbols": num_unproductive_symbols,
            "Number of Inaccessible Symbols": num_inaccessible_symbols,
        }

    def is_recursive(self, symbol, visited):
        """
        Check if a symbol is recursive in the grammar
        :param symbol: The symbol to check recursion for
        :param visited: A set of visited symbols
        :return: True if the symbol is recursive, False otherwise
        """
        if symbol in visited:
            return True
        visited.add(symbol)

        for rule in self.payload_dict[symbol]:
            for token in rule:
                if token in self.payload_dict and self.is_recursive(token, visited):
                    return True
        visited.remove(symbol)
        return False

    def is_productive(self, symbol, visited):
        """
              Check if a symbol is productive in the grammar
              :param symbol: The symbol to check productivity for
              :param visited: Set to keep track of visited symbols (used internally for recursion)
              :return: True if the symbol is productive, False otherwise
              """
        if visited is None:
            visited = set()  # 用于记录已经访问的符号

        # 如果符号已经被访问过，直接返回
        if symbol in visited:
            return False

        visited.add(symbol)

        # 检查每一个产生式规则，查看是否可以生成终结符串
        for production in self.payload_dict[symbol]:
            is_production_productive = True  # 假设产生式是可生成的
            for token in production:
                if token in self.payload_dict:
                    if not self.is_productive(token, visited):
                        is_production_productive = False
                        break
            if is_production_productive:
                return True  # 如果至少有一个产生式是可生成的，返回True

        return False  # 如果所有产生式都不是可生成的，返回False

    def is_non_productive(self, symbol, visited=None):
        """
        Check if a symbol is non-productive in the grammar
        :param symbol: The symbol to check non-productivity for
        :param visited: Set to keep track of visited symbols (used internally for recursion)
        :return: True if the symbol is non-productive, False otherwise
        """
        if visited is None:
            visited = set()  # 用于记录已经访问的符号

        # 如果符号已经被访问过，直接返回
        if symbol in visited:
            return False

        visited.add(symbol)

        # 检查每一个产生式规则，查看是否可以生成终结符串
        for production in self.payload_dict[symbol]:
            is_production_productive = False  # 假设产生式不是可生成的
            for token in production:
                if token in self.payload_dict:
                    if self.is_non_productive(token, visited):
                        is_production_productive = True
                        break
            if is_production_productive:
                return True  # 如果至少有一个产生式是可生成的，返回True

        return False  # 如果所有产生式都不是可生成的，返回False

    def is_terminal(self, symbol):
        """
        Check if a symbol is a terminal
        :param symbol: The symbol to check
        :return: True if the symbol is a terminal, False otherwise
        """
        # If the symbol is not in the dictionary, it is a terminal
        if symbol not in self.payload_dict:
            return True
        # If the symbol maps to a list containing a single string of length 1, it is a terminal
        elif len(self.payload_dict[symbol]) == 1 and len(self.payload_dict[symbol][0]) == 1:
            return True
        else:
            return False

    def is_accessible(self, symbol, current_symbol, visited):
        """
        Check if a symbol is accessible in the grammar
        :param symbol: The symbol to check accessibility for
        :return: True if the symbol is accessible, False otherwise
        """
        if current_symbol in visited:
            return False  # 避免进入无限循环，如果已经访问过该符号，则返回False
        visited.add(current_symbol)

        # 检查当前符号的每一个产生式
        for production in self.payload_dict[current_symbol]:
            for token in production:
                if token == symbol:
                    return True  # 如果找到目标符号，返回True
                if token in self.payload_dict:
                    if self.is_accessible(symbol, token, visited):
                        return True

        return False


if __name__ == "__main__":
    # print(Payload('SQLI').injection)
    # print(Payload('XSS').injection)
    # print(Payload('PHPI').injection)
    # print(Payload('OSI').injection)
    # print(Payload('XMLI').injection)
    # print(Payload('HTMLI').injection)

    print('SQLI Stastistics:')
    Payload('SQLI').grammar_characteristics()

    print('XSS Stastistics:')
    Payload('XSS').grammar_characteristics()

    print('PHPI Stastistics:')
    Payload('PHPI').grammar_characteristics()

    print('OSI Stastistics:')
    Payload('OSI').grammar_characteristics()

    print('XMLI Stastistics:')
    Payload('XMLI').grammar_characteristics()

    print('HTMLI Stastistics:')
    Payload('HTMLI').grammar_characteristics()


