import * as path from 'path';
import { FileUtils } from '../utils/file-utils';
import { serviceTemplate } from '../templates/service.template';
import { controllerTemplate } from '../templates/controller.template';
import { moduleTemplate } from '../templates/module.template';

export function generateModule(name: string, basePath: string = 'src'): void {
  const entityName = FileUtils.toPascalCase(name);
  const camelCaseName = FileUtils.toCamelCase(name);
  const kebabCaseName = FileUtils.toKebabCase(name);
  const entityFileName = kebabCaseName;
  const pluralKebabCase = FileUtils.toKebabCase(FileUtils.pluralize(name));
  const pluralSnakeCase = FileUtils.toSnakeCase(FileUtils.pluralize(name));
  const pluralPascalCase = FileUtils.toPascalCase(FileUtils.pluralize(name));
  const upperSnakeCase = FileUtils.toSnakeCase(
    FileUtils.pluralize(name),
  ).toUpperCase();

  // Define paths
  const modulePath = path.join(basePath, kebabCaseName);
  const entitiesPath = path.join(modulePath, 'entities');
  const dtoPath = path.join(modulePath, 'dto');
  const servicesPath = path.join(modulePath, 'services');
  const controllersPath = path.join(modulePath, 'controllers');

  // File paths
  const entityFilePath = path.join(entitiesPath, `${entityFileName}.entity.ts`);
  const createDtoPath = path.join(dtoPath, `create-${kebabCaseName}.dto.ts`);
  const updateDtoPath = path.join(dtoPath, `update-${kebabCaseName}.dto.ts`);
  const filterDtoPath = path.join(dtoPath, `filter-${kebabCaseName}.dto.ts`);
  const serviceFilePath = path.join(
    servicesPath,
    `${kebabCaseName}.service.ts`,
  );
  const controllerFilePath = path.join(
    controllersPath,
    `${kebabCaseName}.controller.ts`,
  );
  const moduleFilePath = path.join(modulePath, `${kebabCaseName}.module.ts`);

  // Check if module already exists
  if (FileUtils.fileExists(moduleFilePath)) {
    console.error(`❌ Module already exists: ${moduleFilePath}`);
    return;
  }

  // Create directories
  FileUtils.ensureDirectoryExists(entitiesPath);
  FileUtils.ensureDirectoryExists(dtoPath);
  FileUtils.ensureDirectoryExists(servicesPath);
  FileUtils.ensureDirectoryExists(controllersPath);

  // Generate entity if it doesn't exist
  if (!FileUtils.fileExists(entityFilePath)) {
    console.log(`📝 Generating entity: ${entityFilePath}`);
    const entityTemplate = FileUtils.readFile(
      path.join(__dirname, '../templates/entity.template.ts'),
    );
    const entityContent = entityTemplate
      .replace(/{{entityName}}/g, entityName)
      .replace(/{{tableName}}/g, pluralSnakeCase);
    FileUtils.writeFile(entityFilePath, entityContent);
  }

  // Generate DTOs if they don't exist
  if (!FileUtils.fileExists(createDtoPath)) {
    console.log(`📝 Generating create DTO: ${createDtoPath}`);
    const createDtoTemplate = FileUtils.readFile(
      path.join(__dirname, '../templates/create-dto.template.ts'),
    );
    const createDtoContent = createDtoTemplate.replace(
      /{{entityName}}/g,
      entityName,
    );
    FileUtils.writeFile(createDtoPath, createDtoContent);
  }

  if (!FileUtils.fileExists(updateDtoPath)) {
    console.log(`📝 Generating update DTO: ${updateDtoPath}`);
    const updateDtoTemplate = FileUtils.readFile(
      path.join(__dirname, '../templates/update-dto.template.ts'),
    );
    const updateDtoContent = updateDtoTemplate.replace(
      /{{entityName}}/g,
      entityName,
    );
    FileUtils.writeFile(updateDtoPath, updateDtoContent);
  }

  if (!FileUtils.fileExists(filterDtoPath)) {
    console.log(`📝 Generating filter DTO: ${filterDtoPath}`);
    const filterDtoTemplate = FileUtils.readFile(
      path.join(__dirname, '../templates/filter-dto.template.ts'),
    );
    const filterDtoContent = filterDtoTemplate.replace(
      /{{entityName}}/g,
      entityName,
    );
    FileUtils.writeFile(filterDtoPath, filterDtoContent);
  }

  // Generate service content
  const serviceContent = serviceTemplate
    .replace(/{{EntityName}}/g, entityName)
    .replace(/{{camelCaseName}}/g, camelCaseName)
    .replace(/{{kebabCaseName}}/g, kebabCaseName)
    .replace(/{{entityFileName}}/g, entityFileName)
    .replace(/{{entityName}}/g, camelCaseName);

  // Generate controller content
  const controllerContent = controllerTemplate
    .replace(/{{EntityName}}/g, entityName)
    .replace(/{{camelCaseName}}/g, camelCaseName)
    .replace(/{{kebabCaseName}}/g, kebabCaseName)
    .replace(/{{entityFileName}}/g, entityFileName)
    .replace(/{{pluralKebabCase}}/g, pluralKebabCase)
    .replace(/{{pluralLowerCase}}/g, pluralSnakeCase)
    .replace(/{{pluralPascalCase}}/g, pluralPascalCase)
    .replace(/{{UPPER_SNAKE_CASE}}/g, upperSnakeCase);

  // Generate module content
  const moduleContent = moduleTemplate
    .replace(/{{EntityName}}/g, entityName)
    .replace(/{{kebabCaseName}}/g, kebabCaseName)
    .replace(/{{entityFileName}}/g, entityFileName);

  // Write files
  FileUtils.writeFile(serviceFilePath, serviceContent);
  FileUtils.writeFile(controllerFilePath, controllerContent);
  FileUtils.writeFile(moduleFilePath, moduleContent);

  console.log(`✅ Module generated successfully:`);
  console.log(`   📁 ${modulePath}/`);
  console.log(`   ├── entities/${entityFileName}.entity.ts`);
  console.log(`   ├── dto/`);
  console.log(`   │   ├── create-${kebabCaseName}.dto.ts`);
  console.log(`   │   ├── update-${kebabCaseName}.dto.ts`);
  console.log(`   │   └── filter-${kebabCaseName}.dto.ts`);
  console.log(`   ├── services/${kebabCaseName}.service.ts`);
  console.log(`   ├── controllers/${kebabCaseName}.controller.ts`);
  console.log(`   └── ${kebabCaseName}.module.ts`);
  console.log('');
  console.log('📝 Next steps:');
  console.log('   1. Review and customize the generated entity fields');
  console.log('   2. Update DTO validation rules as needed');
  console.log('   3. Customize service logic and search fields');
  console.log('   4. Update controller permissions and endpoints');
  console.log('   5. Add the module to your main app.module.ts');
  console.log(
    `   6. Import { ${entityName}Module } from './${kebabCaseName}/${kebabCaseName}.module';`,
  );
}
