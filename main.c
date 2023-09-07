#include <assert.h>
#include <llvm-c/Analysis.h>
#include <llvm-c/BitWriter.h>
#include <llvm-c/Core.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MAX_PARAMS = 2 };

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

static LLVMValueRef parse_function_call(Lexer *l, LLVMBuilderRef builder);

static LLVMValueRef
parse_expression_or_rparen(Lexer *l, LLVMBuilderRef builder) {
    Token token = next_token(l);
    if (token_is(token, ')')) {
        return NULL;
    } else if (token_is(token, '(')) {
        return parse_function_call(l, builder);
    } else if (is_integer_literal(token)) {
        size_t n = parse_integer_literal(token);
        return LLVMConstInt(LLVMInt64Type(), n, false);
    }
    assert(!"TODO: parse variables");
}

static LLVMValueRef call_function(
    LLVMBuilderRef builder, char const *name, LLVMValueRef args[],
    size_t arg_count
) {
    if (streq(name, "add")) {
        assert(arg_count == 2);
        return LLVMBuildAdd(builder, args[0], args[1], "");
    } else if (streq(name, "mul")) {
        assert(arg_count == 2);
        return LLVMBuildMul(builder, args[0], args[1], "");
    } else if (streq(name, "read")) {
        assert(arg_count == 1);
        LLVMTypeRef i64 = LLVMInt64Type();
        return LLVMBuildLoad2(builder, i64, args[0], "");
    } else if (streq(name, "write")) {
        assert(arg_count == 2);
        LLVMBuildStore(builder, args[1], args[0]);
        return args[1];
    } else if (streq(name, "eq")) {
        assert(arg_count == 2);
        return LLVMBuildIntCast2(
            builder, LLVMBuildICmp(builder, LLVMIntEQ, args[0], args[1], ""),
            LLVMInt64Type(), false, ""
        );
    } else {
        assert(!"unknown function");
    }
}

static LLVMValueRef parse_function_call(Lexer *l, LLVMBuilderRef builder) {
    Token function_name = next_token(l);
    assert(token_is_identifier(function_name));
    char *name = memdupz(function_name.source, function_name.len);

    LLVMValueRef args[MAX_PARAMS];
    size_t arg_count = 0;
    for (;;) {
        LLVMValueRef arg = parse_expression_or_rparen(l, builder);
        if (!arg) {
            break;
        }
        assert(arg_count < MAX_PARAMS);
        args[arg_count] = arg;
        ++arg_count;
    }

    LLVMValueRef res = call_function(builder, name, args, arg_count);
    free(name);
    return res;
}

static LLVMValueRef parse_expression(Lexer *l, LLVMBuilderRef builder) {
    LLVMValueRef expr = parse_expression_or_rparen(l, builder);
    assert(expr);
    return expr;
}

static bool parse_function(Lexer *l, LLVMModuleRef module) {
    Token function_name = next_token(l);
    if (function_name.source == 0) {
        return false;
    }
    assert(token_is_identifier(function_name));

    LLVMTypeRef i64 = LLVMInt64Type();

    size_t param_count = 0;
    LLVMTypeRef param_types[MAX_PARAMS];
    for (;;) {
        Token param_or_lparen = next_token(l);
        if (token_is(param_or_lparen, '(')) {
            break;
        }
        assert(token_is_identifier(param_or_lparen));
        assert(param_count < MAX_PARAMS);
        param_types[param_count] = i64;
        ++param_count;
    }

    LLVMTypeRef function_type =
        LLVMFunctionType(i64, param_types, param_count, false);
    char *name = memdupz(function_name.source, function_name.len);
    LLVMValueRef function = LLVMAddFunction(module, name, function_type);
    free(name);

    LLVMBasicBlockRef entry = LLVMAppendBasicBlock(function, "entry");
    LLVMBuilderRef builder = LLVMCreateBuilder();
    LLVMPositionBuilderAtEnd(builder, entry);
    LLVMValueRef return_value = parse_expression(l, builder);
    LLVMBuildRet(builder, return_value);

    assert(token_is(next_token(l), ')'));

    return true;
}

static void parse(Lexer *l) {
    LLVMModuleRef module = LLVMModuleCreateWithName(NULL);
    LLVMSetTarget(module, "x86_64-pc-linux-gnu");

    while (parse_function(l, module))
        ;

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
