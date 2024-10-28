from pstats import Stats

left = Stats("left.prof")
right = Stats("right.prof")

for stat in [left, right]:
    stat.sort_stats("tottime")
    stat.print_stats(0.02)
