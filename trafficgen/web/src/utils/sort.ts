/**
 * Create a client-side sort comparator function.
 * Returns a function compatible with Array.sort().
 */
export function createClientSort<T>(prop: keyof T, order: string): (a: T, b: T) => number {
  return (a, b) => {
    const aVal = a[prop]
    const bVal = b[prop]
    let result = 0
    if (aVal == null && bVal != null) result = -1
    else if (aVal != null && bVal == null) result = 1
    else if (typeof aVal === 'string' && typeof bVal === 'string') result = aVal.localeCompare(bVal)
    else result = (aVal as number) - (bVal as number)
    return order === 'ascending' ? result : -result
  }
}
