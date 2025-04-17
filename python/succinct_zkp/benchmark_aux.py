import statistics

def get_statistics(timings):
    if len(timings) == 1:
        return timings
    med = statistics.median(timings)
    min_v = min(timings)
    max_v = max(timings)
    stdev = statistics.stdev(timings)
    return f"median={med:.3f}s, min={min_v:.3f}s, max={max_v:.3f}s, std={stdev:.3f}s"