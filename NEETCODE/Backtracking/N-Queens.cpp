#include <vector>
#include <string>
using namespace std;
class Solution
{
public:
    vector<vector<string>> res;
    vector<string> board;
    vector<bool> col, diag1, diag2;
    int n;

    void dfs(int row)
    {
        if (row == n)
        {
            res.push_back(board);
            return;
        }

        for (int c = 0; c < n; c++)
        {
            if (col[c] || diag1[row - c + n] || diag2[row + c])
                continue;

            board[row][c] = 'Q';
            col[c] = diag1[row - c + n] = diag2[row + c] = true;

            dfs(row + 1);

            board[row][c] = '.';
            col[c] = diag1[row - c + n] = diag2[row + c] = false;
        }
    }

    vector<vector<string>> solveNQueens(int N)
    {
        n = N;
        board = vector<string>(n, string(n, '.'));
        col = vector<bool>(n, false);
        diag1 = vector<bool>(2 * n, false); // row - col
        diag2 = vector<bool>(2 * n, false); // row + col

        dfs(0);
        return res;
    }
};
