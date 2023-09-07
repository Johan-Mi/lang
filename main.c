#include <assert.h>
#include <llvm-c/Analysis.h>
#include <llvm-c/BitWriter.h>
#include <llvm-c/Core.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MAX_PARAMS = 2, MAX_VARIABLES = 8, MAX_FUNCTIONS = 8 };

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
    return c == '(' || c == ')';
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

static LLVMValueRef look_up_variable(Variables *vars, char const *name) {
    for (size_t i = 0; i < vars->count; ++i) {
        if (streq(vars->names[i], name), name) {
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
    assert(fns->count < MAX_VARIABLES);
    fns->names[fns->count] = name;
    fns->param_counts[fns->count] = param_count;
    fns->types[fns->count] = type;
    fns->refs[fns->count] = ref;
    ++fns->count;
}

static size_t look_up_function(Functions *fns, char const *name) {
    for (size_t i = 0; i < fns->count; ++i) {
        if (streq(fns->names[i], name), name) {
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
    } else {
        char *variable_name = memdupz(token.source, token.len);
        LLVMValueRef variable_value = look_up_variable(vars, variable_name);
        free(variable_name);
        return variable_value;
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
    } else if (streq(name, "write")) {
        assert(arg_count == 2);
        LLVMTypeRef i64 = LLVMInt64Type();
        LLVMTypeRef ptr_type = LLVMPointerType(i64, 0);
        LLVMValueRef ptr = LLVMBuildIntToPtr(builder, args[0], ptr_type, "");
        LLVMBuildStore(builder, args[1], ptr);
        return args[1];
    } else if (streq(name, "eq")) {
        assert(arg_count == 2);
        return LLVMBuildIntCast2(
            builder, LLVMBuildICmp(builder, LLVMIntEQ, args[0], args[1], ""),
            LLVMInt64Type(), false, ""
        );
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
    for (;;) {
        Token param_or_lparen = next_token(l);
        if (token_is(param_or_lparen, '(')) {
            break;
        }
        assert(token_is_identifier(param_or_lparen));
        assert(param_count < MAX_PARAMS);
        param_names[param_count] =
            memdupz(param_or_lparen.source, param_or_lparen.len);
        param_types[param_count] = i64;
        ++param_count;
    }

    LLVMTypeRef function_type =
        LLVMFunctionType(i64, param_types, param_count, false);
    char *name = memdupz(function_name.source, function_name.len);
    LLVMValueRef function = LLVMAddFunction(module, name, function_type);
    add_function(fns, name, param_count, function_type, function);

    Variables vars = {0};
    for (size_t i = 0; i < param_count; ++i) {
        add_variable(&vars, param_names[i], LLVMGetParam(function, i));
    }

    LLVMBasicBlockRef entry = LLVMAppendBasicBlock(function, "entry");
    LLVMBuilderRef builder = LLVMCreateBuilder();
    LLVMPositionBuilderAtEnd(builder, entry);
    LLVMValueRef return_value = parse_expression(l, builder, &vars, fns);
    LLVMBuildRet(builder, return_value);

    assert(token_is(next_token(l), ')'));

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
