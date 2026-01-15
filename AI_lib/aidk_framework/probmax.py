from typing import Any
import numpy as np

def probmax(val: list[float], outputs: list) -> tuple[Any, float, list[float]]:
    val = np.array(val)
    if val.size == 0:
        raise ValueError("val array is empty")

    min_val = np.min(val)
    if min_val < 0:
        val = val - min_val

    total = np.sum(val)
    if total == 0:
        prob = np.full(val.shape, 1 / val.size)
        return outputs[0], prob[0], prob.tolist()

    prob = val / total
    ind = np.argmax(prob)

    return outputs[ind], prob[ind], prob.tolist()


