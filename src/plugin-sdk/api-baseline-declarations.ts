// Declaration rendering keeps API baseline output stable across compiler contexts.
import path from "node:path";
import ts from "typescript";

const DECLARATION_TYPE_FORMAT_FLAGS =
  ts.TypeFormatFlags.NoTruncation | ts.TypeFormatFlags.MultilineObjectLiterals;
const DECLARATION_NODE_BUILDER_FLAGS = ts.NodeBuilderFlags.NoTruncation;

/** Normalize compiler source paths into stable repo-relative or node_modules-relative paths. */
export function normalizePluginSdkApiSourcePath(repoRoot: string, filePath: string): string {
  const resolvedPath = path.resolve(filePath);
  const relative = path.relative(repoRoot, resolvedPath);
  const relativePosix = relative.split(path.sep).join(path.posix.sep);
  if (
    !relative.startsWith("..") &&
    !path.isAbsolute(relative) &&
    !relativePosix.startsWith("node_modules/")
  ) {
    return relativePosix;
  }

  const pathParts = resolvedPath.split(/[\\/]+/);
  const nodeModulesIndex = pathParts.lastIndexOf("node_modules");
  if (nodeModulesIndex >= 0 && nodeModulesIndex < pathParts.length - 1) {
    return ["node_modules", ...pathParts.slice(nodeModulesIndex + 1)].join(path.posix.sep);
  }

  return relativePosix;
}

function isAbsoluteImportPath(value: string): boolean {
  return path.isAbsolute(value) || /^[A-Za-z]:[\\/]/.test(value);
}

function normalizeDeclarationImportSpecifier(repoRoot: string, value: string): string {
  if (!isAbsoluteImportPath(value)) {
    return value;
  }

  const resolvedPath = path.resolve(value);
  const relative = path.relative(repoRoot, resolvedPath);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    return value;
  }
  return relative.split(path.sep).join(path.posix.sep);
}

/** Strip machine-local absolute paths from declaration text before hashing baseline output. */
export function normalizePluginSdkApiDeclarationText(repoRoot: string, value: string): string {
  return value.replaceAll(
    /import\("([^"]+)"((?:\s*,[^)]*)?)\)/g,
    (match, specifier: string, suffix: string) => {
      const normalized = normalizeDeclarationImportSpecifier(repoRoot, specifier);
      return normalized === specifier ? match : `import("${normalized}"${suffix})`;
    },
  );
}

function declarationModifiers(node: ts.Node): readonly ts.Modifier[] | undefined {
  return ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
}

function inferDeclarationTypeNode(
  checker: ts.TypeChecker,
  declaration: ts.Declaration,
  explicitType: ts.TypeNode | undefined,
): ts.TypeNode | undefined {
  return (
    explicitType ??
    checker.typeToTypeNode(
      checker.getTypeAtLocation(declaration),
      declaration,
      DECLARATION_NODE_BUILDER_FLAGS,
    )
  );
}

function inferDeclarationReturnTypeNode(
  checker: ts.TypeChecker,
  declaration: ts.SignatureDeclaration,
  explicitType: ts.TypeNode | undefined,
): ts.TypeNode | undefined {
  if (explicitType) {
    return explicitType;
  }
  const signature = checker.getSignatureFromDeclaration(declaration);
  return signature
    ? checker.typeToTypeNode(
        checker.getReturnTypeOfSignature(signature),
        declaration,
        DECLARATION_NODE_BUILDER_FLAGS,
      )
    : undefined;
}

function stripParameterInitializer(parameter: ts.ParameterDeclaration): ts.ParameterDeclaration {
  return ts.factory.updateParameterDeclaration(
    parameter,
    declarationModifiers(parameter),
    parameter.dotDotDotToken,
    parameter.name,
    parameter.questionToken,
    parameter.type,
    undefined,
  );
}

function stripClassMemberImplementation(
  checker: ts.TypeChecker,
  member: ts.ClassElement,
): ts.ClassElement | null {
  if (ts.isClassStaticBlockDeclaration(member)) {
    return null;
  }
  if (ts.isConstructorDeclaration(member)) {
    return ts.factory.updateConstructorDeclaration(
      member,
      declarationModifiers(member),
      member.parameters.map(stripParameterInitializer),
      undefined,
    );
  }
  if (ts.isMethodDeclaration(member)) {
    return ts.factory.updateMethodDeclaration(
      member,
      declarationModifiers(member),
      member.asteriskToken,
      member.name,
      member.questionToken,
      member.typeParameters,
      member.parameters.map(stripParameterInitializer),
      inferDeclarationReturnTypeNode(checker, member, member.type),
      undefined,
    );
  }
  if (ts.isGetAccessorDeclaration(member)) {
    return ts.factory.updateGetAccessorDeclaration(
      member,
      declarationModifiers(member),
      member.name,
      member.parameters.map(stripParameterInitializer),
      inferDeclarationReturnTypeNode(checker, member, member.type),
      undefined,
    );
  }
  if (ts.isSetAccessorDeclaration(member)) {
    return ts.factory.updateSetAccessorDeclaration(
      member,
      declarationModifiers(member),
      member.name,
      member.parameters.map(stripParameterInitializer),
      undefined,
    );
  }
  if (ts.isPropertyDeclaration(member)) {
    return ts.factory.updatePropertyDeclaration(
      member,
      declarationModifiers(member),
      member.name,
      member.questionToken ?? member.exclamationToken,
      inferDeclarationTypeNode(checker, member, member.type),
      undefined,
    );
  }
  return member;
}

function stripClassImplementation(
  checker: ts.TypeChecker,
  declaration: ts.ClassDeclaration,
  exportName: string,
): ts.ClassDeclaration {
  const members = declaration.members.flatMap((member) => {
    const stripped = stripClassMemberImplementation(checker, member);
    return stripped ? [stripped] : [];
  });
  return ts.factory.updateClassDeclaration(
    declaration,
    declarationModifiers(declaration),
    ts.factory.createIdentifier(exportName),
    declaration.typeParameters,
    declaration.heritageClauses,
    members,
  );
}

function renameStructuredDeclarationForExport(
  checker: ts.TypeChecker,
  declaration: ts.Declaration,
  exportName: string,
): ts.Declaration {
  const name = ts.factory.createIdentifier(exportName);
  if (ts.isClassDeclaration(declaration)) {
    return stripClassImplementation(checker, declaration, exportName);
  }
  if (ts.isInterfaceDeclaration(declaration)) {
    return ts.factory.updateInterfaceDeclaration(
      declaration,
      declarationModifiers(declaration),
      name,
      declaration.typeParameters,
      declaration.heritageClauses,
      declaration.members,
    );
  }
  if (ts.isEnumDeclaration(declaration)) {
    return ts.factory.updateEnumDeclaration(
      declaration,
      declarationModifiers(declaration),
      name,
      declaration.members,
    );
  }
  if (ts.isModuleDeclaration(declaration) && ts.isIdentifier(declaration.name)) {
    return ts.factory.updateModuleDeclaration(
      declaration,
      declarationModifiers(declaration),
      name,
      declaration.body,
    );
  }
  return declaration;
}

function ensureExportedDeclarationText(value: string): string {
  return /^export\b/u.test(value) ? value : `export ${value}`;
}

function printTypeParameters(printer: ts.Printer, declaration: ts.TypeAliasDeclaration): string {
  if (!declaration.typeParameters?.length) {
    return "";
  }
  const sourceFile = declaration.getSourceFile();
  const parameters = declaration.typeParameters.map((typeParameter) =>
    printer.printNode(ts.EmitHint.Unspecified, typeParameter, sourceFile).trim(),
  );
  return `<${parameters.join(", ")}>`;
}

/** Render tuple-derived literal unions in declaration order, independent of compiler traversal. */
export function formatPluginSdkApiTypeAlias(
  checker: ts.TypeChecker,
  declaration: ts.TypeAliasDeclaration,
): string {
  const type = checker.getTypeAtLocation(declaration);
  if (
    type.isUnion() &&
    ts.isIndexedAccessTypeNode(declaration.type) &&
    declaration.type.indexType.kind === ts.SyntaxKind.NumberKeyword
  ) {
    const tuple = checker.getTypeFromTypeNode(declaration.type.objectType);
    const members = checker.isTupleType(tuple)
      ? [...new Set(checker.getTypeArguments(tuple as ts.TypeReference))]
      : [];
    if (
      members.length === type.types.length &&
      members.every(
        (member) =>
          (member.isStringLiteral() || member.isNumberLiteral()) && type.types.includes(member),
      )
    ) {
      return members
        .map((member) => checker.typeToString(member, declaration, DECLARATION_TYPE_FORMAT_FLAGS))
        .join(" | ");
    }
  }
  return checker.typeToString(type, declaration, DECLARATION_TYPE_FORMAT_FLAGS);
}

/** Print a declaration as a stable public SDK export. */
export function printPluginSdkApiDeclaration(params: {
  repoRoot: string;
  checker: ts.TypeChecker;
  printer: ts.Printer;
  declaration: ts.Declaration;
  exportName: string;
}): string | null {
  const { repoRoot, checker, printer, declaration, exportName } = params;
  if (ts.isFunctionDeclaration(declaration)) {
    const signatures = checker.getTypeAtLocation(declaration).getCallSignatures();
    if (signatures.length === 0) {
      return `export function ${exportName}();`;
    }
    return normalizePluginSdkApiDeclarationText(
      repoRoot,
      signatures
        .map(
          (signature) =>
            `export function ${exportName}${checker.signatureToString(
              signature,
              declaration,
              DECLARATION_TYPE_FORMAT_FLAGS,
            )};`,
        )
        .join("\n"),
    );
  }

  if (ts.isVariableDeclaration(declaration)) {
    const type = checker.getTypeAtLocation(declaration);
    const prefix =
      declaration.parent && (ts.getCombinedNodeFlags(declaration.parent) & ts.NodeFlags.Const) !== 0
        ? "const"
        : "let";
    return normalizePluginSdkApiDeclarationText(
      repoRoot,
      `export ${prefix} ${exportName}: ${checker.typeToString(
        type,
        declaration,
        DECLARATION_TYPE_FORMAT_FLAGS,
      )};`,
    );
  }

  if (ts.isTypeAliasDeclaration(declaration)) {
    const typeParameters = printTypeParameters(printer, declaration);
    return normalizePluginSdkApiDeclarationText(
      repoRoot,
      `export type ${exportName}${typeParameters} = ${formatPluginSdkApiTypeAlias(checker, declaration)};`,
    );
  }

  const printableDeclaration = renameStructuredDeclarationForExport(
    checker,
    declaration,
    exportName,
  );
  const text = printer
    .printNode(ts.EmitHint.Unspecified, printableDeclaration, declaration.getSourceFile())
    .trim();
  if (!text) {
    return null;
  }
  return normalizePluginSdkApiDeclarationText(repoRoot, ensureExportedDeclarationText(text));
}

/** Deterministically order declarations that can originate from re-exported modules. */
export function comparePluginSdkApiDeclarations(
  repoRoot: string,
  left: ts.Declaration,
  right: ts.Declaration,
): number {
  const leftPath = normalizePluginSdkApiSourcePath(repoRoot, left.getSourceFile().fileName);
  const rightPath = normalizePluginSdkApiSourcePath(repoRoot, right.getSourceFile().fileName);
  return (
    compareText(leftPath, rightPath) || left.getStart() - right.getStart() || left.kind - right.kind
  );
}

function compareText(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}
