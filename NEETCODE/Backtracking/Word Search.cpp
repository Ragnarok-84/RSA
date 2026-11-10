#include <vector>
#include <string>
using namespace std;
class Solution
{
public:
    int m, n;
    vector<vector<char>> *b;
    string w;

    bool dfs(int i, int j, int k)
    {
        // All characters matched
        if (k == w.size())
            return true;

        // Out of bounds or mismatch
        if (i < 0 || j < 0 || i >= m || j >= n || (*b)[i][j] != w[k])
            return false;

        char temp = (*b)[i][j];
        (*b)[i][j] = '#'; // mark visited

        bool found =
            dfs(i + 1, j, k + 1) ||
            dfs(i - 1, j, k + 1) ||
            dfs(i, j + 1, k + 1) ||
            dfs(i, j - 1, k + 1);

        (*b)[i][j] = temp; // backtrack
        return found;
    }

    bool exist(vector<vector<char>> &board, string word)
    {
        m = board.size();
        n = board[0].size();
        b = &board;
        w = word;

        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < n; j++)
            {
                if (dfs(i, j, 0))
                    return true;
            }
        }
        return false;
    }
};
