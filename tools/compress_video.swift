import AVFoundation
import Foundation

guard CommandLine.arguments.count == 3 else {
    fputs("usage: swift compress_video.swift <input> <output>\n", stderr)
    exit(2)
}

let inputURL = URL(fileURLWithPath: CommandLine.arguments[1])
let outputURL = URL(fileURLWithPath: CommandLine.arguments[2])

try? FileManager.default.removeItem(at: outputURL)

let asset = AVURLAsset(url: inputURL)
let compatiblePresets = AVAssetExportSession.exportPresets(compatibleWith: asset)
let preset = compatiblePresets.contains(AVAssetExportPreset1280x720)
    ? AVAssetExportPreset1280x720
    : AVAssetExportPresetMediumQuality

guard let exporter = AVAssetExportSession(asset: asset, presetName: preset) else {
    fputs("Could not create export session.\n", stderr)
    exit(1)
}

exporter.outputURL = outputURL
exporter.outputFileType = .mp4
exporter.shouldOptimizeForNetworkUse = true

let semaphore = DispatchSemaphore(value: 0)
exporter.exportAsynchronously {
    semaphore.signal()
}

while semaphore.wait(timeout: .now() + 0.5) == .timedOut {
    let percent = Int(exporter.progress * 100)
    print("progress \(percent)%")
}

switch exporter.status {
case .completed:
    print("completed \(outputURL.path)")
case .failed:
    fputs("Export failed: \(exporter.error?.localizedDescription ?? "unknown error")\n", stderr)
    exit(1)
case .cancelled:
    fputs("Export cancelled.\n", stderr)
    exit(1)
default:
    fputs("Export ended with status \(exporter.status.rawValue).\n", stderr)
    exit(1)
}
