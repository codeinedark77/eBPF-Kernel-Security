const fs = require('fs');
const path = require('path');

function fixFile(filePath) {
    let content = fs.readFileSync(filePath, 'utf8');
    
    // Reverse the mangled json.RawMessage(..., nil) -> json.RawMessage(...)
    content = content.replace(/json\.RawMessage\(`([^`]*)`, nil\)/g, 'json.RawMessage(`$1`)');
    content = content.replace(/json\.RawMessage\(([^,]+), nil\)/g, 'json.RawMessage($1)');
    
    // Reverse e.Evaluate(e.Evaluate( -> e.Evaluate(
    content = content.replace(/e\.Evaluate\(e\.Evaluate\(/g, 'e.Evaluate(');
    
    // Now safely add , nil to all e.Evaluate calls that only have 3 args.
    // e.Evaluate(arg1, arg2, arg3) -> e.Evaluate(arg1, arg2, arg3, nil)
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
        let line = lines[i];
        if (line.includes('e.Evaluate(')) {
            // Very simple replacement: if line doesn't end with `, nil)`, and we can find the matching paren...
            // It's easier: just replace `, detail)` with `, detail, nil)`
            // And `, d)` with `, d, nil)`
            // And `, json.RawMessage(...)` with `, json.RawMessage(...), nil`
            line = line.replace(/, detail\)/g, ', detail, nil)');
            line = line.replace(/, d1\)/g, ', d1, nil)');
            line = line.replace(/, d\)/g, ', d, nil)');
            line = line.replace(/, json\.RawMessage\(`([^`]+)`\)\)/g, ', json.RawMessage(`$1`), nil)');
            line = line.replace(/, json\.RawMessage\(fmt\.Sprintf\(`([^`]+)`, (.*?)\)\)\)/g, ', json.RawMessage(fmt.Sprintf(`$1`, $2)), nil)');
            
            // cleanup any accidental doubles
            line = line.replace(/, nil, nil\)/g, ', nil)');
            lines[i] = line;
        }
    }
    
    fs.writeFileSync(filePath, lines.join('\n'));
}

fixFile('internal/rules/rules_test.go');
fixFile('internal/rules/gaps_test.go');
console.log('Fixed');
