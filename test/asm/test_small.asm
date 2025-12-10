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
