class GlobalOffset(gdb.Command):
    def __init__(self):
        super(GlobalOffset, self).__init__("global-offset", gdb.COMMAND_USER)
    
    def invoke(self, args, from_tty):
        args = args.split(' ')
        if len(args) != 1:
            raise gdb.GdbError("global-offset expects exactly one argument")
        symbol = gdb.lookup_global_symbol(args[0])
        if symbol is None:
            raise gdb.GdbError("symbol {} was not found in global context".format(args[0]))
        print(int(symbol.value().address))

GlobalOffset()
