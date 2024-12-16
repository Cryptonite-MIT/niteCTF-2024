import matplotlib.font_manager as fm
import matplotlib.pyplot as plt
import librosa
import numpy as np
from pydub import AudioSegment


def extract_notes(wav_path):
    y, sr = librosa.load(wav_path)
    hop_length = 512
    onset_frames = librosa.onset.onset_detect(
        y=y, sr=sr, hop_length=hop_length)

    onset_times = librosa.frames_to_time(
        onset_frames, sr=sr, hop_length=hop_length)

    pitches, magnitudes = librosa.core.piptrack(
        y=y, sr=sr, hop_length=hop_length)
    notes = []
    for t in onset_frames:
        index = magnitudes[:, t].argmax()
        pitch = pitches[index, t]
        if pitch > 0:
            note = librosa.hz_to_midi(pitch)
            notes.append(librosa.midi_to_note(note))

    return onset_times, notes


mappings = {
    "anfang_": ["G4", "A4", "B4", "C5", "D5"],
    "a": ["G4", "B4", "A4", "C5", "B4"],
    "b": ["G5", "D5", "B4", "G4", "G4"],
    "c": ["B4", "D5", "C5", "E5", "D5"],
    "d": ["G4", "B4", "A4", "G4"],
    "e": ["E5", "D5", "C5", "B4", "A4", "G4"],
    "f": ["B4", "C5", "D5", "B4", "G4"],
    "g": ["B4", "G4", "D5", "B4", "G5"],
    "h": ["E5", "F♯5", "G5", "D5"],
    "i": ["G5", "F♯5", "E5", "D5", "C5"],
    # "j": ["G5", "F♯5", "E5", "D5", "C5"],
    "k": ["D5", "C5", "C5", "B4", "B4"],
    "l": ["B4", "G4", "G4", "B4", "A4"],
    "m": ["E5", "D5", "E5", "C5", "D5"],
    "n": ["F♯4", "A4", "F♯4", "D4"],
    "o": ["E5", "C♯5", "E5", "A4"],
    "p": ["F♯4", "G4", "A4", "F♯4", "D4"],
    "q": ["B4", "G4", "F♯4", "G4", "A4"],
    "r": ["F♯4", "E4", "E4", "D4", "D4"],
    "s": ["G4", "B4", "A4", "C5", "B4", "D5"],
    "t": ["B4", "A4", "B4", "G4", "A4"],
    "u": ["F♯4", "G4", "A4"],
    "v": ["F♯5", "F♯5", "E5", "F♯5"],
    "w": ["G5", "G5", "F♯5", "G5", "D5"],
    "x": ["C♯5", "D5", "E5", "C♯5", "A4"],
    # "y": ["G5", "F♯5", "E5", "D5", "C5"],
    "z": ["A5", "G5", "F♯5", "E5", "D5"],
    "_finale": ["G4", "B4", "D5", "G5", "A4", "F♯5", "G5"]
}

onset_times, extracted_notes = extract_notes('bucking.wav')
print(extracted_notes)


def find_character(chunk):
    for char, notes in mappings.items():
        if chunk == notes:
            return char
    return "?"


decoded_message = ""
i = 0

while i < len(extracted_notes):
    for length in sorted(set(len(notes) for notes in mappings.values()), reverse=True):
        chunk = extracted_notes[i:i + length]
        character = find_character(chunk)
        if character != "?":
            decoded_message += character
            i += length
            break
    else:
        decoded_message += "?"
        i += 1

print("Decoded message:", decoded_message)
'''
#to decode subtitles
'''

font_path = 'Buckbeak.otf'
fake_font = fm.FontProperties(fname=font_path)

with open('track_2.ass', 'r', encoding='utf-8') as file:
    lines = file.readlines()

subtitles = []
in_events = False
for line in lines:
    if line.startswith('[Events]'):
        in_events = True
    elif in_events:
        if line.startswith('Dialogue:'):
            text = line.split(',', 9)[-1].strip()
            subtitles.append(text)

for i, subtitle in enumerate(subtitles):
    plt.figure(figsize=(10, 2))
    plt.text(0.5, 0.5, subtitle, fontproperties=fake_font,
             ha='center', va='center', fontsize=20)
    plt.axis('off')
    plt.savefig(f'subtitle_{i}.png')
    plt.close()

print("Subtitles rendered and saved as images.")
