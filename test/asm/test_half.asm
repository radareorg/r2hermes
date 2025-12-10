# Test comprehensive assembler coverage

# Basic register operations
Mov r0, r1
MovLong r0, r1

# Unary operations
Negate r0, r1
Not r0, r1
BitNot r0, r1

# Binary operations
Add r0, r1, r2
Sub r0, r1, r2
Mul r0, r1, r2
Div r0, r1, r2
Mod r0, r1, r2

# Bitwise operations
BitAnd r0, r1, r2
BitOr r0, r1, r2
BitXor r0, r1, r2
LShift r0, r1, r2
RShift r0, r1, r2
URshift r0, r1, r2

# Comparison operations
Eq r0, r1, r2
StrictEq r0, r1, r2
Neq r0, r1, r2
StrictNeq r0, r1, r2
Less r0, r1, r2
Greater r0, r1, r2
LessEq r0, r1, r2
GreaterEq r0, r1, r2

# Load constants
LoadConstZero r0
LoadConstUndefined r0
LoadConstNull r0
LoadConstTrue r0
LoadConstFalse r0
LoadConstEmpty r0
LoadConstString r0, 0x1234
LoadConstStringLongIndex r0, 0x12345678
LoadConstBigInt r0, 0x1234
LoadConstBigIntLongIndex r0, 0x12345678
LoadConstDouble r0, 3.14159
LoadConstInt r0, 0x12345678

# Load parameters
LoadParam r0, 5
LoadParamLong r0, 0x12345678

# Jumps
Jmp 0x10
JmpLong 0x12345678
JmpTrue 0x10, r0
JmpFalse 0x10, r0
JmpUndefined 0x10, r0
JmpTrueLong r0, 0x12345678
JmpFalseLong r0, 0x12345678
JmpUndefinedLong r0, 0x12345678

# Calls
Call r0, r1, 3
CallLong r0, r1, 0x12345678
Construct r0, r1, 3
ConstructLong r0, r1, 0x12345678
CallDirect r0, 3, 0x1234
CallDirectLongIndex r0, 3, 0x12345678
CallBuiltin r0, 5, 3
CallBuiltinLong r0, 5, 0x12345678

