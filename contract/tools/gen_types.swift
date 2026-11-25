// Generates contract/units.json and contract/category.json from the SDK header HKTypeIdentifiers.h.
// Run on a Mac from the repo root:  swift contract/tools/gen_types.swift
// units.json: every quantity identifier that resolves at runtime; entries already in the file are kept as they are.
// category.json: every category identifier that resolves. Deprecated identifiers and workout types are skipped.
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

let excluded: Set<String> = [
    "HKQuantityTypeIdentifierWorkoutEffortScore",
    "HKQuantityTypeIdentifierEstimatedWorkoutEffortScore",
]
let percentOverrides: Set<String> = [
    "HKQuantityTypeIdentifierWalkingAsymmetryPercentage",
    "HKQuantityTypeIdentifierWalkingDoubleSupportPercentage",
    "HKQuantityTypeIdentifierAppleWalkingSteadiness",
    "HKQuantityTypeIdentifierBloodAlcoholContent",
    "HKQuantityTypeIdentifierPeripheralPerfusionIndex",
]
let candidates = ["count/min", "count", "kcal", "s", "m", "g", "%", "degC", "mL", "mmHg", "dBASPL", "m/s", "W", "IU",
                  "mL/min·kg", "S", "lx", "V", "Hz", "L/min", "kcal/hr·kg"]

let header = sdkPath() + "/System/Library/Frameworks/HealthKit.framework/Headers/HKTypeIdentifiers.h"
let lines = try! String(contentsOfFile: header, encoding: .utf8).components(separatedBy: "\n")
let re = try! NSRegularExpression(pattern: "HK(Quantity|Category)TypeIdentifier[A-Za-z0-9]+")

var quantity = Set<String>(), category = Set<String>()
for line in lines where !line.contains("API_DEPRECATED") {
    for m in re.matches(in: line, range: NSRange(line.startIndex..., in: line)) {
        let name = String(line[Range(m.range, in: line)!])
        if excluded.contains(name) { continue }
        if name.hasPrefix("HKQuantity") { quantity.insert(name) } else { category.insert(name) }
    }
}

let root = FileManager.default.currentDirectoryPath + "/contract/"
let old = (try? JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: root + "units.json"))) as? [String: String]) ?? [:]

var units: [String: String] = [:], missing: [String] = []
for name in quantity.sorted() {
    guard let type = HKQuantityType.quantityType(forIdentifier: HKQuantityTypeIdentifier(rawValue: name)) else { continue }
    if let u = old[name] { units[name] = u; continue }
    if percentOverrides.contains(name) { units[name] = "%"; continue }
    if let u = candidates.first(where: { type.is(compatibleWith: HKUnit(from: $0)) }) { units[name] = u } else { missing.append(name) }
}
let cats = category.sorted().filter {
    HKCategoryType.categoryType(forIdentifier: HKCategoryTypeIdentifier(rawValue: $0)) != nil
}

func write(_ obj: Any, _ file: String) {
    let d = try! JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    try! (String(decoding: d, as: UTF8.self) + "\n").write(toFile: root + file, atomically: true, encoding: .utf8)
}
write(units, "units.json")
write(cats, "category.json")
if !missing.isEmpty {
    FileHandle.standardError.write(Data(("no compatible unit: " + missing.joined(separator: ", ") + "\n").utf8))
    exit(1)
}
print("units: \(units.count), categories: \(cats.count)")
