import nltk
import numpy as np
nltk.download('wordnet', quiet=True)
from nltk.corpus import wordnet as wn

nouns = set(wn.all_lemma_names(pos='n'))

with open('aidk/words.txt', 'r') as file:
    word_list = set(line.strip().lower() for line in file)

words = list(word_list.union(nouns))
words.sort()

for i in "`~@#$%^*().!,<>;':\"/?\\|[]{}-_=+ ":
    words.append(str(i))

words.append("")

words, tokens = {i: words[i] for i in range(len(words))}, {words[i]: i for i in range(len(words))}

def flatten(lst):
    for item in lst:
        if isinstance(item, list):
            yield from flatten(item)
        else:
            yield item

def split_by_chars(s, char_list):
    result = []
    word = ""
    for ch in s:
        if ch in char_list:
            if word:
                result.append(word)
                word = ""
            result.append(ch)
        else:
            word += ch
    if word:
        result.append(word)
    return result

def tokenize(text:str) -> list:
    text = list(np.array([i for i in flatten([text])]).flatten())
    text = [word.lower() for word in text]
    text = flatten([split_by_chars(i, [i2 for i2 in "`~@#$%^*().!,<>;':\"/?\\|[]{}-_=+ "]) for i in text])
    
    return [tokens[i] for i in text]

def untokenize(token_text: list) -> str:
    text = "".join([words[int(0 if 0 > i else i if i < len(words) else len(words) - 1)] + " " for i in flatten(token_text)])
    return text


