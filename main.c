#include <assert.h>
#include <llvm-c/Analysis.h>
#include <llvm-c/BitWriter.h>
#include <llvm-c/Core.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MAX_PARAMS = 5, MAX_VARIABLES = 8, MAX_FUNCTIONS = 128 };

static void assert_errno(bool condition, char const *message) {
    if (!condition) {
        perror(message);
        exit(EXIT_FAILURE);
    }
}

static char *memdupz(char const *ptr, size_t len) {
    char *res = malloc(len + 1);
    assert(res);
    memcpy(res, ptr, len);
    res[len] = '\0';
    return res;
}

static bool streq(char const *a, char const *b) {
    return !strcmp(a, b);
}

static bool is_whitespace(char c) {
    return c == ' ' || c == '\t' || c == '\n';
}

static bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

static bool is_alphabetic(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static bool is_identifier_part(char c) {
    return is_alphabetic(c) || is_digit(c) || c == '_';
}

static bool is_single_character_token(char c) {
    return c == '(' || c == ')' || c == '.';
}

typedef struct {
    char *line;
    size_t len;
    size_t cap;
    FILE *file;
    char *full_line;
} Lexer;

typedef struct {
    char const *source;
    size_t len;
} Token;

static void bump(Lexer *l, size_t byte_count) {
    l->line += byte_count;
    l->len -= byte_count;
}

static void remove_comment(Lexer *l) {
    char const *comment = memchr(l->line, '#', l->len);
    if (comment) {
        l->len = comment - l->line;
    }
}

static bool read_next_line(Lexer *l) {
    l->len = getline(&l->full_line, &l->cap, l->file);
    l->line = l->full_line;
    if (feof(l->file)) {
        return false;
    }
    assert_errno(l->len != (size_t)-1, "failed to read source code");
    remove_comment(l);
    return true;
}

static void skip_whitespace(Lexer *l) {
    while (l->len != 0 && is_whitespace(*l->line)) {
        bump(l, 1);
    }
}

static bool find_start_of_next_token(Lexer *l) {
    while (skip_whitespace(l), l->len == 0) {
        if (!read_next_line(l)) {
            return false;
        }
    }
    return true;
}

static size_t next_token_length(Lexer *l) {
    if (is_single_character_token(*l->line)) {
        return 1;
    }
    assert(is_identifier_part(*l->line) && "invalid character in source code");
    size_t i = 1;
    while (i < l->len && is_identifier_part(l->line[i])) {
        ++i;
    }
    return i;
}

static Token next_token(Lexer *l) {
    if (!find_start_of_next_token(l)) {
        return (Token){0};
    }
    size_t len = next_token_length(l);
    char const *source = l->line;
    bump(l, len);
    return (Token){source, len};
}

static bool token_is_identifier(Token token) {
    return token.source && !is_single_character_token(*token.source);
}

static bool token_is(Token token, char c) {
    return token.source && *token.source == c;
}

static bool token_eq_str(Token token, char const *s) {
    size_t len = strlen(s);
    return token.len == len && !memcmp(token.source, s, len);
}

static bool is_integer_literal(Token token) {
    for (size_t i = 0; i < token.len; ++i) {
        if (!is_digit(token.source[i])) {
            return false;
        }
    }
    return true;
}

static size_t parse_integer_literal(Token token) {
    size_t n = 0;
    for (size_t i = 0; i < token.len; ++i) {
        n *= 10;
        n += token.source[i] - '0';
    }
    return n;
}

typedef struct {
    char *names[MAX_VARIABLES];
    LLVMValueRef values[MAX_VARIABLES];
    size_t count;
} Variables;

static void add_variable(Variables *vars, char *name, LLVMValueRef value) {
    assert(vars->count < MAX_VARIABLES);
    vars->names[vars->count] = name;
    vars->values[vars->count] = value;
    ++vars->count;
}

static void remove_variable(Variables *vars) {
    --vars->count;
    free(vars->names[vars->count]);
}

static LLVMValueRef look_up_variable(Variables *vars, Token name) {
    for (size_t i = vars->count; i > 0;) {
        --i;
        if (token_eq_str(name, vars->names[i])) {
            return vars->values[i];
        }
    }
    assert(!"unknown variable");
}

typedef struct {
    char *names[MAX_FUNCTIONS];
    size_t param_counts[MAX_FUNCTIONS];
    LLVMTypeRef types[MAX_FUNCTIONS];
    LLVMValueRef refs[MAX_FUNCTIONS];
    size_t count;
} Functions;

static void add_function(
    Functions *fns, char *name, size_t param_count, LLVMTypeRef type,
    LLVMValueRef ref
) {
    assert(fns->count < MAX_FUNCTIONS);
    fns->names[fns->count] = name;
    fns->param_counts[fns->count] = param_count;
    fns->types[fns->count] = type;
    fns->refs[fns->count] = ref;
    ++fns->count;
}

static size_t look_up_function(Functions *fns, char const *name) {
    for (size_t i = 0; i < fns->count; ++i) {
        if (streq(fns->names[i], name)) {
            return i;
        }
    }
    assert(!"unknown variable");
}

static void clear_functions(Functions *fns) {
    for (size_t i = 0; i < fns->count; ++i) {
        free(fns->names[i]);
    }
}

static LLVMValueRef parse_function_call(
    Lexer *l, LLVMBuilderRef builder, Variables *vars, Functions *fns
);

static LLVMValueRef parse_expression(
    Lexer *l, LLVMBuilderRef builder, Variables *vars, Functions *fns
);

static LLVMValueRef parse_expression_or_rparen(
    Lexer *l, LLVMBuilderRef builder, Variables *vars, Functions *fns
);

static LLVMValueRef
parse_if(Lexer *l, LLVMBuilderRef builder, Variables *vars, Functions *fns) {
    LLVMTypeRef i64 = LLVMInt64Type();
    LLVMValueRef condition = parse_expression(l, builder, vars, fns);
    LLVMValueRef bool_condition = LLVMBuildICmp(
        builder, LLVMIntNE, condition, LLVMConstInt(i64, 0, false), ""
    );

    LLVMValueRef func = LLVMGetBasicBlockParent(LLVMGetInsertBlock(builder));

    LLVMBasicBlockRef then_block = LLVMAppendBasicBlock(func, "");
    LLVMBasicBlockRef else_block = LLVMAppendBasicBlock(func, "");
    LLVMBasicBlockRef after_block = LLVMAppendBasicBlock(func, "");
    LLVMBuildCondBr(builder, bool_condition, then_block, else_block);

    LLVMPositionBuilderAtEnd(builder, then_block);
    LLVMValueRef then = parse_expression(l, builder, vars, fns);
    LLVMBasicBlockRef then_end_block = LLVMGetInsertBlock(builder);
    LLVMBuildBr(builder, after_block);

    LLVMPositionBuilderAtEnd(builder, else_block);
    LLVMValueRef else_ = parse_expression(l, builder, vars, fns);
    LLVMBasicBlockRef else_end_block = LLVMGetInsertBlock(builder);
    LLVMBuildBr(builder, after_block);

    LLVMPositionBuilderAtEnd(builder, after_block);
    LLVMValueRef phi = LLVMBuildPhi(builder, i64, "");
    LLVMValueRef incoming_values[] = {then, else_};
    LLVMBasicBlockRef incoming_blocks[] = {then_end_block, else_end_block};
    LLVMAddIncoming(phi, incoming_values, incoming_blocks, 2);
    return phi;
}

static LLVMValueRef
parse_block(Lexer *l, LLVMBuilderRef builder, Variables *vars, Functions *fns) {
    LLVMValueRef res = NULL;
    for (;;) {
        LLVMValueRef step = parse_expression_or_rparen(l, builder, vars, fns);
        if (!step) {
            return res ? res : LLVMConstInt(LLVMInt64Type(), 0, false);
        }
        res = step;
    }
}

static LLVMValueRef
parse_let(Lexer *l, LLVMBuilderRef builder, Variables *vars, Functions *fns) {
    Token var_name = next_token(l);
    assert(token_is_identifier(var_name));
    char *name = memdupz(var_name.source, var_name.len);
    LLVMValueRef value = parse_expression(l, builder, vars, fns);
    add_variable(vars, name, value);
    LLVMValueRef res = parse_expression(l, builder, vars, fns);
    remove_variable(vars);
    return res;
}

static LLVMValueRef
parse_while(Lexer *l, LLVMBuilderRef builder, Variables *vars, Functions *fns) {
    LLVMValueRef func = LLVMGetBasicBlockParent(LLVMGetInsertBlock(builder));

    LLVMBasicBlockRef check = LLVMAppendBasicBlock(func, "");
    LLVMBasicBlockRef loop = LLVMAppendBasicBlock(func, "");
    LLVMBasicBlockRef after = LLVMAppendBasicBlock(func, "");

    LLVMBuildBr(builder, check);
    LLVMPositionBuilderAtEnd(builder, check);
    LLVMValueRef condition = parse_expression(l, builder, vars, fns);
    LLVMTypeRef i64 = LLVMInt64Type();
    LLVMValueRef bool_condition = LLVMBuildICmp(
        builder, LLVMIntNE, condition, LLVMConstInt(i64, 0, false), ""
    );
    LLVMBuildCondBr(builder, bool_condition, loop, after);

    LLVMPositionBuilderAtEnd(builder, loop);
    parse_expression(l, builder, vars, fns);
    LLVMBuildBr(builder, check);

    LLVMPositionBuilderAtEnd(builder, after);
    return LLVMConstInt(i64, 0, false);
}

static LLVMValueRef
parse_and(Lexer *l, LLVMBuilderRef builder, Variables *vars, Functions *fns) {
    LLVMValueRef lhs = parse_expression(l, builder, vars, fns);
    LLVMTypeRef i64 = LLVMInt64Type();
    LLVMValueRef bool_lhs =
        LLVMBuildICmp(builder, LLVMIntNE, lhs, LLVMConstInt(i64, 0, false), "");
    LLVMBasicBlockRef this_block = LLVMGetInsertBlock(builder);
    LLVMValueRef func = LLVMGetBasicBlockParent(this_block);
    LLVMBasicBlockRef rhs_block = LLVMAppendBasicBlock(func, "");
    LLVMBasicBlockRef after = LLVMAppendBasicBlock(func, "");
    LLVMBuildCondBr(builder, bool_lhs, rhs_block, after);

    LLVMPositionBuilderAtEnd(builder, rhs_block);
    LLVMValueRef rhs = parse_expression(l, builder, vars, fns);
    LLVMBuildBr(builder, after);
    LLVMBasicBlockRef rhs_end_block = LLVMGetInsertBlock(builder);

    LLVMPositionBuilderAtEnd(builder, after);
    LLVMValueRef phi = LLVMBuildPhi(builder, i64, "");
    LLVMValueRef incoming_values[] = {LLVMConstInt(i64, 0, false), rhs};
    LLVMBasicBlockRef incoming_blocks[] = {this_block, rhs_end_block};
    LLVMAddIncoming(phi, incoming_values, incoming_blocks, 2);
    return phi;
}

static LLVMValueRef
parse_or(Lexer *l, LLVMBuilderRef builder, Variables *vars, Functions *fns) {
    LLVMValueRef lhs = parse_expression(l, builder, vars, fns);
    LLVMTypeRef i64 = LLVMInt64Type();
    LLVMValueRef bool_lhs =
        LLVMBuildICmp(builder, LLVMIntNE, lhs, LLVMConstInt(i64, 0, false), "");
    LLVMBasicBlockRef this_block = LLVMGetInsertBlock(builder);
    LLVMValueRef func = LLVMGetBasicBlockParent(this_block);
    LLVMBasicBlockRef rhs_block = LLVMAppendBasicBlock(func, "");
    LLVMBasicBlockRef after = LLVMAppendBasicBlock(func, "");
    LLVMBuildCondBr(builder, bool_lhs, after, rhs_block);

    LLVMPositionBuilderAtEnd(builder, rhs_block);
    LLVMValueRef rhs = parse_expression(l, builder, vars, fns);
    LLVMBuildBr(builder, after);
    LLVMBasicBlockRef rhs_end_block = LLVMGetInsertBlock(builder);

    LLVMPositionBuilderAtEnd(builder, after);
    LLVMValueRef phi = LLVMBuildPhi(builder, i64, "");
    LLVMValueRef incoming_values[] = {lhs, rhs};
    LLVMBasicBlockRef incoming_blocks[] = {this_block, rhs_end_block};
    LLVMAddIncoming(phi, incoming_values, incoming_blocks, 2);
    return phi;
}

static LLVMValueRef parse_expression_or_rparen(
    Lexer *l, LLVMBuilderRef builder, Variables *vars, Functions *fns
) {
    Token token = next_token(l);
    if (token_is(token, ')')) {
        return NULL;
    } else if (token_is(token, '(')) {
        return parse_function_call(l, builder, vars, fns);
    } else if (is_integer_literal(token)) {
        size_t n = parse_integer_literal(token);
        return LLVMConstInt(LLVMInt64Type(), n, false);
    } else if (token_eq_str(token, "if")) {
        return parse_if(l, builder, vars, fns);
    } else if (token_eq_str(token, "do")) {
        assert(token_is(next_token(l), '('));
        return parse_block(l, builder, vars, fns);
    } else if (token_eq_str(token, "let")) {
        return parse_let(l, builder, vars, fns);
    } else if (token_eq_str(token, "while")) {
        return parse_while(l, builder, vars, fns);
    } else if (token_eq_str(token, "and")) {
        return parse_and(l, builder, vars, fns);
    } else if (token_eq_str(token, "or")) {
        return parse_or(l, builder, vars, fns);
    } else {
        assert(token_is_identifier(token));
        return look_up_variable(vars, token);
    }
}

static LLVMValueRef call_function(
    LLVMBuilderRef builder, Functions *fns, char const *name,
    LLVMValueRef args[], size_t arg_count
) {
    if (streq(name, "add")) {
        assert(arg_count == 2);
        return LLVMBuildAdd(builder, args[0], args[1], "");
    } else if (streq(name, "sub")) {
        assert(arg_count == 2);
        return LLVMBuildSub(builder, args[0], args[1], "");
    } else if (streq(name, "mul")) {
        assert(arg_count == 2);
        return LLVMBuildMul(builder, args[0], args[1], "");
    } else if (streq(name, "read")) {
        assert(arg_count == 1);
        LLVMTypeRef i64 = LLVMInt64Type();
        LLVMTypeRef ptr_type = LLVMPointerType(i64, 0);
        LLVMValueRef ptr = LLVMBuildIntToPtr(builder, args[0], ptr_type, "");
        return LLVMBuildLoad2(builder, i64, ptr, "");
    } else if (streq(name, "read8")) {
        assert(arg_count == 1);
        LLVMTypeRef i8 = LLVMInt8Type();
        LLVMTypeRef i64 = LLVMInt64Type();
        LLVMTypeRef ptr_type = LLVMPointerType(i64, 0);
        LLVMValueRef ptr = LLVMBuildIntToPtr(builder, args[0], ptr_type, "");
        return LLVMBuildIntCast2(
            builder, LLVMBuildLoad2(builder, i8, ptr, ""), i64, false, ""
        );
    } else if (streq(name, "write")) {
        assert(arg_count == 2);
        LLVMTypeRef i64 = LLVMInt64Type();
        LLVMTypeRef ptr_type = LLVMPointerType(i64, 0);
        LLVMValueRef ptr = LLVMBuildIntToPtr(builder, args[0], ptr_type, "");
        LLVMBuildStore(builder, args[1], ptr);
        return args[1];
    } else if (streq(name, "write8")) {
        assert(arg_count == 2);
        LLVMTypeRef i8 = LLVMInt8Type();
        LLVMTypeRef ptr_type = LLVMPointerType(i8, 0);
        LLVMValueRef ptr = LLVMBuildIntToPtr(builder, args[0], ptr_type, "");
        LLVMValueRef value = LLVMBuildIntCast2(builder, args[1], i8, false, "");
        LLVMBuildStore(builder, value, ptr);
        return LLVMBuildIntCast2(builder, value, LLVMInt64Type(), false, "");
    } else if (streq(name, "eq")) {
        assert(arg_count == 2);
        return LLVMBuildIntCast2(
            builder, LLVMBuildICmp(builder, LLVMIntEQ, args[0], args[1], ""),
            LLVMInt64Type(), false, ""
        );
    } else if (streq(name, "lt")) {
        assert(arg_count == 2);
        return LLVMBuildIntCast2(
            builder, LLVMBuildICmp(builder, LLVMIntULT, args[0], args[1], ""),
            LLVMInt64Type(), false, ""
        );
    } else if (streq(name, "alloca")) {
        assert(arg_count == 1);
        LLVMValueRef ptr =
            LLVMBuildArrayAlloca(builder, LLVMInt64Type(), args[0], "");
        return LLVMBuildPtrToInt(builder, ptr, LLVMInt64Type(), "");
    } else if (streq(name, "memcpy")) {
        assert(arg_count == 3);
        LLVMTypeRef i64 = LLVMInt64Type();
        LLVMTypeRef ptr_type = LLVMPointerType(i64, 0);
        LLVMValueRef dest = LLVMBuildIntToPtr(builder, args[0], ptr_type, "");
        LLVMValueRef src = LLVMBuildIntToPtr(builder, args[1], ptr_type, "");
        return LLVMBuildMemCpy(builder, dest, 1, src, 1, args[2]);
    } else {
        size_t i = look_up_function(fns, name);
        assert(arg_count == fns->param_counts[i]);
        return LLVMBuildCall2(
            builder, fns->types[i], fns->refs[i], args, arg_count, ""
        );
        assert(!"unknown function");
    }
}

static LLVMValueRef parse_function_call(
    Lexer *l, LLVMBuilderRef builder, Variables *vars, Functions *fns
) {
    Token function_name = next_token(l);
    assert(token_is_identifier(function_name));
    char *name = memdupz(function_name.source, function_name.len);

    LLVMValueRef args[MAX_PARAMS];
    size_t arg_count = 0;
    for (;;) {
        LLVMValueRef arg = parse_expression_or_rparen(l, builder, vars, fns);
        if (!arg) {
            break;
        }
        assert(arg_count < MAX_PARAMS);
        args[arg_count] = arg;
        ++arg_count;
    }

    LLVMValueRef res = call_function(builder, fns, name, args, arg_count);
    free(name);
    return res;
}

static LLVMValueRef parse_expression(
    Lexer *l, LLVMBuilderRef builder, Variables *vars, Functions *fns
) {
    LLVMValueRef expr = parse_expression_or_rparen(l, builder, vars, fns);
    assert(expr);
    return expr;
}

static bool parse_function(Lexer *l, LLVMModuleRef module, Functions *fns) {
    Token function_name = next_token(l);
    if (function_name.source == 0) {
        return false;
    }
    assert(token_is_identifier(function_name));

    LLVMTypeRef i64 = LLVMInt64Type();

    size_t param_count = 0;
    char *param_names[MAX_PARAMS];
    LLVMTypeRef param_types[MAX_PARAMS];
    bool is_extern = false;
    for (;;) {
        Token token = next_token(l);
        if (token_is(token, '(')) {
            break;
        } else if (token_is(token, '.')) {
            is_extern = true;
            break;
        }
        assert(token_is_identifier(token));
        assert(param_count < MAX_PARAMS);
        param_names[param_count] = memdupz(token.source, token.len);
        param_types[param_count] = i64;
        ++param_count;
    }

    LLVMTypeRef function_type =
        LLVMFunctionType(i64, param_types, param_count, false);
    char *name = memdupz(function_name.source, function_name.len);
    LLVMValueRef function = LLVMAddFunction(module, name, function_type);
    add_function(fns, name, param_count, function_type, function);

    if (is_extern) {
        for (size_t i = 0; i < param_count; ++i) {
            free(param_names[i]);
        }
        return true;
    }

    Variables vars = {0};
    for (size_t i = 0; i < param_count; ++i) {
        add_variable(&vars, param_names[i], LLVMGetParam(function, i));
    }

    LLVMBasicBlockRef entry = LLVMAppendBasicBlock(function, "");
    LLVMBuilderRef builder = LLVMCreateBuilder();
    LLVMPositionBuilderAtEnd(builder, entry);
    LLVMValueRef return_value = parse_block(l, builder, &vars, fns);
    LLVMBuildRet(builder, return_value);

    for (size_t i = 0; i < param_count; ++i) {
        remove_variable(&vars);
    }

    return true;
}

static void parse(Lexer *l) {
    LLVMModuleRef module = LLVMModuleCreateWithName(NULL);
    LLVMSetTarget(module, "x86_64-pc-linux-gnu");

    Functions fns = {0};

    while (parse_function(l, module, &fns))
        ;

    clear_functions(&fns);

    LLVMVerifyModule(module, LLVMAbortProcessAction, NULL);
    LLVMWriteBitcodeToFile(module, "program.bc");
    LLVMDisposeModule(module);
}

int main(int argc, char const *const argv[]) {
    assert(argc >= 2 && "no file provided");
    assert(argc == 2 && "too many command line arguments");
    char const *file_path = argv[1];

    Lexer lexer = {0};
    lexer.file = fopen(file_path, "r");
    assert_errno(lexer.file, "failed to read source code");

    parse(&lexer);

    free(lexer.full_line);
    assert_errno(!fclose(lexer.file), "failed to read source code");
}
