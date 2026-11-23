using System.Text;

namespace TsOrch.Cli;

internal sealed class TextTable(params IReadOnlyList<string> headers)
{
    private const string Gap = "  ";

    private readonly List<IReadOnlyList<string>> _rows = [];

    public void Add(params IReadOnlyList<string> cells)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(cells.Count, headers.Count);
        _rows.Add(cells);
    }

    public void WriteTo(TextWriter writer)
    {
        ArgumentNullException.ThrowIfNull(writer);
        var widths = new int[headers.Count];
        foreach (var row in _rows.Prepend(headers))
        {
            for (var column = 0; column < row.Count; column++)
            {
                widths[column] = Math.Max(widths[column], row[column].Length);
            }
        }

        foreach (var row in _rows.Prepend(headers))
        {
            var line = new StringBuilder();
            for (var column = 0; column < row.Count; column++)
            {
                line.Append(column == 0 ? string.Empty : Gap).Append(column == row.Count - 1 ? row[column] : row[column].PadRight(widths[column]));
            }

            writer.WriteLine(line.ToString().TrimEnd());
        }
    }
}
