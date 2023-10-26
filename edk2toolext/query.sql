-- SQLite
WITH variable AS (
    SELECT
        '50706d9d802242578650ae97875d135a' AS env -- VARIABLE: Change this to the environment parse you care about
)
SELECT
    inf_list.path AS "INF Path",
    junction.key2 AS "Source Path"
FROM
    (
        SELECT
            DISTINCT instanced_inf.path
        FROM
            variable,
            instanced_fv
            JOIN junction ON instanced_fv.env = junction.env
            AND junction.table1 = 'instanced_fv'
            AND junction.table2 = 'inf'
            JOIN instanced_inf ON instanced_inf.component = junction.key2
        WHERE
            instanced_fv.env = variable.env
    ) inf_list,
    variable
    JOIN junction ON junction.key1 = inf_list.path
    AND junction.table2 = 'source'
    AND junction.env = variable.env
    LEFT JOIN source ON source.path = junction.key2
    LEFT JOIN inf ON inf.path = inf_list.path
ORDER BY
    inf_list.path