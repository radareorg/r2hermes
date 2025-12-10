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

# Property access
GetById r0, r1, 0, 0x1234
GetByIdLong r0, r1, 0, 0x12345678
GetByIdShort r0, r1, 0, 0xAB
PutById r0, r1, 0, 0x1234
PutByIdLong r0, r1, 0, 0x12345678
GetByVal r0, r1, r2
PutByVal r0, r1, r2

# Environment operations
StoreToEnvironment r0, 5, r1
StoreToEnvironmentL r0, 0x1234, r1
LoadFromEnvironment r0, r1, 5
LoadFromEnvironmentL r0, r1, 0x1234

# Object/array creation
NewObject r0
NewObjectWithParent r0, r1
NewArray r0, 10

# Control flow
Ret r0
Catch r0
Throw r0
ThrowIfEmpty r0, r1

# Type operations
TypeOf r0, r1
InstanceOf r0, r1, r2
ToNumber r0, r1
ToNumeric r0, r1
ToInt32 r0, r1

# Special operations
Unreachable
Debugger
AsyncBreakCheck
ProfilePoint 0x1234

# Generator operations
StartGenerator
ResumeGenerator r0, r1
CompleteGenerator
CreateGenerator r0, r1, 0x1234
CreateGeneratorLongIndex r0, r1, 0x12345678

# Closure operations
CreateClosure r0, r1, 0x1234
CreateClosureLongIndex r0, r1, 0x12345678
CreateGeneratorClosure r0, r1, 0x1234
CreateGeneratorClosureLongIndex r0, r1, 0x12345678
CreateAsyncClosure r0, r1, 0x1234
CreateAsyncClosureLongIndex r0, r1, 0x12345678

# This operations
CoerceThisNS r0, r1
LoadThisNS r0
CreateThis r0, r1, r2
SelectObject r0, r1, r2

# Arguments
GetArgumentsPropByVal r0, r1, r2
GetArgumentsLength r0, r1
ReifyArguments r0

# Global operations
DeclareGlobalVar 0x12345678
ThrowIfHasRestrictedGlobalProperty 0x12345678
GetGlobalObject r0
GetNewTarget r0

# Environment creation
CreateEnvironment r0
CreateInnerEnvironment r0, r1, 0x12345678

# Builtin operations
GetBuiltinClosure r0, 5

# RegExp
CreateRegExp r0, 0x12345678, 0x12345678, 0x12345678

# Switch
SwitchImm r0, 0x12345678, 0x12345678, 0x12345678, 0x12345678

# Iterator operations
IteratorBegin r0, r1
IteratorNext r0, r1, r2
IteratorClose r0, 1

# Property enumeration
GetPNameList r0, r1, r2, r3
GetNextPName r0, r1, r2, r3, r4

# Property operations
PutOwnByVal r0, r1, r2, 0
DelById r0, r1, 0x1234
DelByIdLong r0, r1, 0x12345678
DelByVal r0, r1, r2

# Advanced property operations
PutNewOwnByIdShort r0, r1, 0xAB
PutNewOwnById r0, r1, 0x1234
PutNewOwnByIdLong r0, r1, 0x12345678
PutNewOwnNEById r0, r1, 0x1234
PutNewOwnNEByIdLong r0, r1, 0x12345678
PutOwnByIndex r0, r1, 5
PutOwnByIndexL r0, r1, 0x12345678
PutOwnGetterSetterByVal r0, r1, r2, r3, 0

# Numeric operations
AddN r0, r1, r2
SubN r0, r1, r2
MulN r0, r1, r2
DivN r0, r1, r2
Inc r0, r1
Dec r0, r1
AddEmptyString r0, r1

# Comparison jumps
JLess 0x10, r0, r1
JLessLong 0x12345678, r0, r1
JNotLess 0x10, r0, r1
JNotLessLong 0x12345678, r0, r1
JLessN 0x10, r0, r1
JLessNLong 0x12345678, r0, r1
JNotLessN 0x10, r0, r1
JNotLessNLong 0x12345678, r0, r1
JLessEqual 0x10, r0, r1
JLessEqualLong 0x12345678, r0, r1
JNotLessEqual 0x10, r0, r1
JNotLessEqualLong 0x12345678, r0, r1
JLessEqualN 0x10, r0, r1
JLessEqualNLong 0x12345678, r0, r1
JNotLessEqualN 0x10, r0, r1
JNotLessEqualNLong 0x12345678, r0, r1
JGreater 0x10, r0, r1
JGreaterLong 0x12345678, r0, r1
JNotGreater 0x10, r0, r1
JNotGreaterLong 0x12345678, r0, r1
JGreaterN 0x10, r0, r1
JGreaterNLong 0x12345678, r0, r1
JNotGreaterN 0x10, r0, r1
JNotGreaterNLong 0x12345678, r0, r1
JGreaterEqual 0x10, r0, r1
JGreaterEqualLong 0x12345678, r0, r1
JNotGreaterEqual 0x10, r0, r1
JNotGreaterEqualLong 0x12345678, r0, r1
JGreaterEqualN 0x10, r0, r1
JGreaterEqualNLong 0x12345678, r0, r1
JNotGreaterEqualN 0x10, r0, r1
JNotGreaterEqualNLong 0x12345678, r0, r1
JEqual 0x10, r0, r1
JEqualLong 0x12345678, r0, r1
JNotEqual 0x10, r0, r1
JNotEqualLong 0x12345678, r0, r1
JStrictEqual 0x10, r0, r1
JStrictEqualLong 0x12345678, r0, r1
JStrictNotEqual 0x10, r0, r1
JStrictNotEqualLong 0x12345678, r0, r1

# Typed operations
Add32 r0, r1, r2
Sub32 r0, r1, r2
Mul32 r0, r1, r2
Divi32 r0, r1, r2
Divu32 r0, r1, r2
Loadi8 r0, r1, r2
Loadu8 r0, r1, r2
Loadi16 r0, r1, r2
Loadu16 r0, r1, r2
Loadi32 r0, r1, r2
Loadu32 r0, r1, r2
Store8 r0, r1, r2
Store16 r0, r1, r2
Store32 r0, r1, r2

# Try operations
TryGetById r0, r1, 0, 0x1234
TryGetByIdLong r0, r1, 0, 0x12345678
TryPutById r0, r1, 0, 0x1234
TryPutByIdLong r0, r1, 0, 0x12345678

# Direct eval
DirectEval r0, r1, 0

# IsIn
IsIn r0, r1, r2

# ThrowIfUndefinedInst
ThrowIfUndefinedInst r0