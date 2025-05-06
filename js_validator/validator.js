const vm = require('vm');
const util = require('util');

if (process.argv.length < 4) {
    console.error(JSON.stringify({ success: false, error: 'Eksik argüman: Kod ve Kriterler gerekli.' }));
    process.exit(1);
}

let userCode;
let criteria;
try {
    userCode = Buffer.from(process.argv[2], 'base64').toString('utf8');
    criteria = JSON.parse(Buffer.from(process.argv[3], 'base64').toString('utf8'));
} catch (e) {
    console.error(JSON.stringify({ success: false, error: `Argümanlar çözümlenemedi: ${e.message}` }));
    process.exit(1);
}

const capturedConsole = [];
const sandbox = {
    console: {
        log: (...args) => {
            capturedConsole.push(args.map(arg => util.format(arg)).join(' '));
        },
    },
    require: undefined,
    process: undefined,
    setTimeout: undefined,
    setInterval: undefined,
    Math: Math,
};

const context = vm.createContext(sandbox);
const result = {
    success: false,
    message: 'Doğrulama tamamlanamadı.',
    consoleOutput: [],
    finalChecks: {},
    error: null,
};

try {
    vm.runInContext(userCode, context, { timeout: 2000 });

    result.consoleOutput = capturedConsole;
    let allChecksPassed = true;

    if (criteria.expectedConsoleOutput && Array.isArray(criteria.expectedConsoleOutput)) {
        if (capturedConsole.length !== criteria.expectedConsoleOutput.length) {
            allChecksPassed = false;
            result.message = `Beklenen konsol çıktısı sayısı (${criteria.expectedConsoleOutput.length}) ile gerçek çıktı sayısı (${capturedConsole.length}) eşleşmiyor.`;
        } else {
            for (let i = 0; i < criteria.expectedConsoleOutput.length; i++) {
                if (capturedConsole[i] !== criteria.expectedConsoleOutput[i]) {
                    allChecksPassed = false;
                    result.message = `${i + 1}. konsol çıktısı beklenenden farklı. Beklenen: '${criteria.expectedConsoleOutput[i]}', Gelen: '${capturedConsole[i]}'.`;
                    break;
                }
            }
        }
    }

    if (allChecksPassed && criteria.variableChecks && Array.isArray(criteria.variableChecks)) {
        for (const check of criteria.variableChecks) {
            const varName = check.name;
            const expectedValue = check.expectedValue;
            let actualValue;
            try {
                actualValue = vm.runInContext(varName, context);
            } catch (e) {
                allChecksPassed = false;
                result.message = `'${varName}' adlı değişken kodunuzda tanımlanmamış veya erişilemiyor.`;
                break;
            }
            if (JSON.stringify(actualValue) !== JSON.stringify(expectedValue)) {
                 allChecksPassed = false;
                 result.message = `'${varName}' değişkeninin değeri beklenenden farklı. Beklenen: ${JSON.stringify(expectedValue)}, Gelen: ${JSON.stringify(actualValue)}.`;
                 break;
            }
             result.finalChecks[varName] = actualValue;
        }
    }

    if (allChecksPassed) {
        result.success = true;
        result.message = 'Kod başarıyla çalıştı ve kontrolleri geçti.';
    }

} catch (e) {
    result.success = false;
    result.error = e.toString();
    result.message = `Kod çalıştırılırken hata oluştu: ${e.name || 'Error'} - ${e.message || result.error}`;
}

process.stdout.write(JSON.stringify(result));