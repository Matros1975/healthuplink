// Generates contract/cumulative.json: HKQuantityType identifiers whose aggregationStyle is .cumulative.
// Run on a Mac:  swift contract/tools/gen_cumulative.swift > contract/cumulative.json
// Identifiers are read from the SDK header HKTypeIdentifiers.h, so new SDKs pick up new types.
import Foundation
import HealthKit

func sdkPath() -> String {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
    p.arguments = ["--show-sdk-path"]
    let pipe = Pipe()
    p.standardOutput = pipe
    try! p.run()
    p.waitUntilExit()
    return String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        .trimmingCharacters(in: .whitespacesAndNewlines)
}

let header = sdkPath() + "/System/Library/Frameworks/HealthKit.framework/Headers/HKTypeIdentifiers.h"
let text = try! String(contentsOfFile: header, encoding: .utf8)
let re = try! NSRegularExpression(pattern: "HKQuantityTypeIdentifier[A-Za-z0-9]+")
let names = Set(re.matches(in: text, range: NSRange(text.startIndex..., in: text)).map {
    String(text[Range($0.range, in: text)!])
})
var out: [String] = []
for name in names.sorted() {
    guard let type = HKQuantityType.quantityType(forIdentifier: HKQuantityTypeIdentifier(rawValue: name)) else { continue }
    if type.aggregationStyle == .cumulative { out.append(name) }
}
let data = try! JSONSerialization.data(withJSONObject: out.sorted(), options: [.prettyPrinted])
print(String(decoding: data, as: UTF8.self))
