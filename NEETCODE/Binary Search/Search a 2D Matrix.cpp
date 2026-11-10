#include <vector>
using namespace std;
class Solution1
{
public:
    bool search(vector<int> &nums, int target)
    {
        int l = 0, r = nums.size() - 1;
        while (l <= r)
        {
            int mid = (l + r) / 2;
            if (nums[mid] == target)
            {
                return true;
            }
            else if (nums[mid] < target)
            {
                l = mid + 1;
            }
            else
            {
                r = mid - 1;
            }
        }
        return false;
    }
    bool searchMatrix(vector<vector<int>> &matrix, int target)
    {
        int n = matrix.size();
        int m = matrix[0].size();

        vector<int> v;
        v.reserve(n * m);

        for (const auto &row : matrix)
        {
            v.insert(v.end(), row.begin(), row.end());
        }

        return search(v, target);
    }
};

class Solution2
{
public:
    bool searchMatrix(vector<vector<int>> &matrix, int target)
    {
        int m = matrix.size();
        int n = matrix[0].size();

        int left = 0, right = m * n - 1;

        while (left <= right)
        {
            int mid = left + (right - left) / 2;

            int r = mid / n;
            int c = mid % n;

            int val = matrix[r][c];

            if (val == target)
                return true;
            else if (val < target)
                left = mid + 1;
            else
                right = mid - 1;
        }
        return false;
    }
};
