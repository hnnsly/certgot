# certgot: замечания по UX/DX-изменениям

## Назначение

Этот файл — инструкция следующему агенту. Исправить замечания по порядку. Не удалять или ослаблять существующие гарантии: атомарную публикацию cert/key, storage lock, проверку сертификатов, strict YAML, systemd hardening и корректные exit codes.

## Исходный статус

На момент review:

- `go test ./... -race -cover` проходит;
- покрытие основного пакета: 49.4%;
- покрытие `internal/storage`: 67.9%;
- `go vet ./...` проходит;
- `gofmt` и `git diff --check` проходят;
- обычный test suite не запускает Pebble integration из-за build tag.

## Правила работы

1. Сначала выполнить `git status --short`. Не перезаписывать чужие изменения.
2. Каждый пункт исправлять отдельным логическим коммитом.
3. Не выполнять production ACME-запросы.
4. Не менять публичный YAML/JSON/CLI-контракт без обратной совместимости или документированной миграции.
5. После каждого пункта запускать:

```bash
gofmt -w *.go internal/**/*.go
go test ./...
go test ./... -race -cover
go vet ./...
git diff --check
```

6. После исправления integration-кода отдельно запустить локальный Pebble scenario, если сеть и окружение доступны:

```bash
just integration
```

## 1. [P1] Переносить `env_file` при managed setup

Основные места:

- `certs.go`: `loadConfig` делает относительный `env_file` абсолютным;
- `setup.go`: `installConfig` переносит только inline `Env`;
- `setup.go`: systemd включает `ProtectHome=true`;
- `readme.md` и `config-example.yml` рекомендуют `env_file: ./cloudflare.env`.

### Проблема

Документированный сценарий:

```bash
certgot init --env-file ./cloudflare.env
sudo certgot setup --config ./config.yml --setup-interval 2w --yes
```

оставляет в `/etc/certgot/config.yml` абсолютный путь к исходному `cloudflare.env`. Если файл находится в `/home/...`, managed service не может прочитать его из-за `ProtectHome=true`. Renewal падает на загрузке credentials.

### Требуемое исправление

1. В `installConfig` обрабатывать и inline `Env`, и существующий `EnvFile`.
2. Для каждого сертификата создавать управляемый файл:

```text
/etc/certgot/secrets/<index>-<domain>.env
```

3. Для `EnvFile`:
   - прочитать исходный файл;
   - провалить setup при ошибке чтения/парсинга;
   - записать содержимое в managed secrets directory;
   - установить `root:certgot` и `0640`;
   - переписать `cert.EnvFile` в installed config.
4. Для inline `Env` сохранить текущую миграцию в managed env-file.
5. Не оставлять inline credentials в installed YAML.
6. Не менять исходный пользовательский config.
7. Добавить тесты:
   - относительный env-file переносится;
   - абсолютный env-file переносится;
   - inline env переносится;
   - отсутствующий env-file останавливает setup;
   - installed YAML содержит только managed path;
   - permissions/ownership проверяются там, где позволяет OS test environment.

### Критерий приемки

После setup managed config не ссылается на `/home`, рабочую копию проекта или другой исходный путь. Runtime user читает credentials из `/etc/certgot/secrets`.

## 2. [P1] Обеспечить запись файлов в consumer group

Основные места:

- `setup.go`: service запускается как `User=certgot`, `Group=certgot`;
- `certs.go`: `applyFileAccess` вызывает `os.Chown(path, uid, configuredGID)`;
- `config-example.yml`: используется `group: www-data`.

### Проблема

Непривилегированный пользователь `certgot` не может менять группу файла на `www-data`, `nginx` или другую группу, если не состоит в ней. Setup создает только пользователя/группу `certgot` и не добавляет runtime user в группы сертификатов. Типовой renewal падает на `chown`.

### Требуемое исправление

Выбрать и реализовать одну модель. Предпочтительно:

1. Собрать уникальные `certificates[].group` во время setup.
2. Проверить существование каждой группы до установки service.
3. Добавить их в generated unit через безопасно отрендеренный:

```ini
SupplementaryGroups=www-data nginx
```

4. Не выполнять shell interpolation.
5. Валидировать group name.
6. Если группа отсутствует, setup должен завершиться понятной ошибкой до изменения systemd units.
7. Обновить `.github/systemd/certgot.service` и unit verification fixture.
8. Добавить тесты:
   - группы дедуплицируются;
   - пустые group пропускаются;
   - некорректное имя отклоняется;
   - service template содержит ожидаемые supplementary groups;
   - config без consumer groups сохраняет рабочий unit.

Допустимая альтернатива: ACL или узкий privileged deploy helper. Если выбран другой вариант, документировать причину и покрыть теми же сценариями.

### Критерий приемки

Managed renewal с `group: www-data` успешно публикует `0640` cert/key, доступные runtime user и consumer group.

## 3. [P1] Полностью изолировать staging от production

Основные места:

- `renew.go`: `--staging` передает только `RunOptions.Staging`;
- `app.go`: staging использует обычные `accountDir`, `certDir`, lock и reload hooks;
- `app.go`: `newLegoClientWithOptions` повторно использует `user.Registration`, если она уже существует.

### Проблема

`renew --force --staging` использует production storage:

- production account registration повторно используется с другим ACME directory;
- staging registration не отделена от production registration;
- тестовый сертификат может заменить production `current`;
- после публикации могут выполниться `reload_units` и тестовый сертификат попадет в nginx.

### Требуемое исправление

1. Разделить account state по ACME directory identity.
2. Не использовать одну registration для production, staging и custom CA.
3. Для `--staging` использовать отдельное state namespace, например:

```text
accounts/staging/
certs-staging/<domain>/
```

4. Не менять production `certs/<domain>/current`.
5. Не выполнять production `reload_units` в staging mode.
6. Явно маркировать output как staging.
7. Рассмотреть более безопасный контракт: `--staging` требует `--dry-run` либо отдельный `--staging-storage`.
8. Custom `acme_directory_url` также должен иметь отдельную account identity; URL можно хешировать в namespace.
9. Добавить тесты:
   - production registration не передается staging client;
   - staging registration сохраняется отдельно;
   - production current не меняется;
   - reload manager не вызывается;
   - output показывает staging mode;
   - повторный staging run использует только staging account.

### Критерий приемки

Ни один staging/custom-CA запуск не может заменить production certificate pair, изменить production account registration или перезагрузить production service.

## 4. [P1] Сделать `reload_units` работоспособным в managed mode

Основные места:

- `deploy.go`: вызывает `systemctl reload <unit>`;
- `setup.go`: service работает как `certgot` и использует `NoNewPrivileges=true`;
- `readme.md`: reload_units описан как готовая функция.

### Проблема

Системный пользователь `certgot` обычно не авторизован перезагружать `nginx.service` и другие system units. `systemctl reload` завершится `Access denied`/polkit error. Сертификат уже опубликован, но каждый run будет считаться неуспешным.

### Требуемое исправление

Выбрать безопасный механизм. Возможные варианты:

1. Узкий root helper, принимающий только заранее разрешенные unit names.
2. Статическая polkit policy, разрешающая пользователю `certgot` только reload units из config/setup allowlist.
3. Отдельный root-owned systemd path/service механизм, реагирующий на опубликованный release.
4. Отказ от managed reload с явной документацией и warning вместо обещания функции.

Запрещено:

- общий passwordless sudo для `systemctl`;
- выполнение shell-строк из config;
- разрешение произвольного unit name без setup-time allowlist.

Дополнительно:

1. Валидировать `reload_units` в `validateConfig` и `doctor`, до renewal.
2. Проверять существование/допустимость unit во время setup.
3. Четко определить повторный запуск reload после уже опубликованного сертификата. Сейчас повторный `renew` увидит valid cert и не повторит failed reload.
4. Сохранить состояние pending reload либо предоставить отдельную команду retry.
5. Добавить тесты authorization failure, retry, unknown unit, multiple units и частичный failure.

### Критерий приемки

Managed happy path реально перезагружает разрешенный consumer unit либо функция явно отключена и не обещана пользователю.

## 5. [P1] Исправить Telegram environment references

Основные места:

- `certs.go`: `loadConfig` заменяет `${TELEGRAM_URL}` через `os.Getenv`;
- `setup.go`: `installConfig` marshals уже измененный config;
- `setup.go`: generated service не получает Telegram environment variable;
- `init.go`: рекомендует `${TELEGRAM_URL}`.

### Проблема

Во время setup reference раскрывается слишком рано:

- если env доступен, token может попасть в installed YAML через legacy `telegram_url`;
- если sudo отфильтровал env, installed value становится пустым;
- systemd service не получает переменную, поэтому reference не работает в managed mode.

### Требуемое исправление

1. Разделить raw config value и effective runtime value.
2. `loadConfig` не должен мутировать сериализуемое поле секретным значением.
3. Выполнять resolution непосредственно перед notification transport.
4. При `${NAME}` различать:
   - переменная задана;
   - переменная отсутствует;
   - syntax reference некорректен.
5. `doctor` должен возвращать error `TELEGRAM_URL is not available`, а не warning `telegram disabled`, если reference задан.
6. Для managed mode установить безопасный источник переменной:
   - managed EnvironmentFile с `root:certgot 0640`; или
   - systemd LoadCredential/credential file.
7. Не писать раскрытый token в `/etc/certgot/config.yml`, stdout, stderr или JSON.
8. Добавить тесты:
   - raw reference сохраняется после load/install;
   - runtime resolution работает;
   - missing variable видна doctor;
   - token отсутствует в marshaled YAML и logs;
   - managed unit получает разрешенный secret source.

### Критерий приемки

`${TELEGRAM_URL}` работает после reboot в managed service и никогда не превращается в plaintext token внутри installed YAML.

## 6. [P2] Стабилизировать JSON enum статусов

Основные места:

- `certs.go`: внутренние статусы содержат пробелы (`not yet valid`, `wrong domain`);
- `output.go`: `certificateStatusName` преобразует только часть статусов;
- `readme.md`: обещает hyphenated machine values.

### Проблема

JSON может вернуть:

```json
{"status":"not yet valid"}
{"status":"wrong domain"}
```

Документация обещает стабильные значения вроде `not-yet-valid`. Машинные consumers получают незадокументированный enum.

### Требуемое исправление

1. Явно сопоставить каждый `certificateStatus` публичному значению:

```text
missing
malformed
not-yet-valid
wrong-domain
key-mismatch
renewal
valid
error
```

2. Не использовать прямой `string(status)` для публичного JSON.
3. Решить, нужен ли version field для JSON schema. Если нет, зафиксировать schema в README и golden tests.
4. Добавить table-driven тест всех внутренних статусов.
5. Добавить golden JSON с `not-yet-valid`, `wrong-domain`, `key-mismatch`, `renewal`.
6. Использовать те же enum values в text/doctor/renew reason fields, где уместно.

### Критерий приемки

JSON status всегда принадлежит документированному enum; ни одно значение не содержит пробелы.

## 7. [P2] Синхронизировать `renew --dry-run` с реальным renew

Основные места:

- `renew.go`: malformed, key mismatch и wrong domain маркируются `failed`;
- `certs.go`: настоящий process пытается перевыпустить любой сертификат, кроме valid вне force mode.

### Проблема

Dry-run сообщает failure и возвращает exit code 1 для состояний, которые настоящий renew обработает как причины перевыпуска. Preview не соответствует будущему действию.

### Требуемое исправление

1. Для всех состояний, запускающих ACME issuance, возвращать `would-renew`.
2. Добавить отдельное поле причины:

```json
{
  "domain": "example.com",
  "status": "would-renew",
  "reason": "key-mismatch"
}
```

3. `forced` использовать только при `--force`.
4. `skipped` использовать только для valid без force.
5. `failed` использовать для невозможности выполнить проверку: unsafe path, unreadable storage, invalid config и подобных ошибок.
6. Dry-run не должен создавать account, lock, directory, ACME client/order или менять storage.
7. Добавить table-driven тесты для всех certificate statuses и force/non-force combinations.

### Критерий приемки

Dry-run точно показывает действие следующего настоящего renew; repairable certificate state не считается command failure.

## Дополнительные проверки после P1/P2

После обязательных пунктов проверить и при необходимости отдельными коммитами улучшить:

1. `certgot <command> --help` должен показывать help конкретной команды, а не только global help.
2. `setup` не должен скрывать полезный flag usage через `io.Discard`.
3. `doctor` должен использовать `GET` для ACME directory и считать 4xx ошибкой/warning, а не доступностью.
4. `notifications.on` должен валидировать только `always`, `renewed`, `error`; опечатки не должны молча отключать сообщения.
5. `just tidy-check` не должен оставлять измененные `go.mod`/`go.sum` в рабочем дереве при failure.
6. CI systemd fixtures не должны расходиться с runtime templates; желательно генерировать их из одного источника.

## Финальная приемка

Агент должен предоставить:

1. Краткий список исправлений по пунктам 1–7.
2. Список измененных публичных контрактов.
3. Новые тесты для каждого пункта.
4. Вывод:

```bash
go test ./...
go test ./... -race -cover
go vet ./...
git diff --check
```

5. Coverage до/после относительно baseline 49.4% и 67.9%.
6. Результат `systemd-analyze verify` на Linux.
7. Результат `just integration` или точное объяснение блокера.
8. Smoke-test managed config transformation без production ACME:
   - source env-file перенесен;
   - installed config не содержит исходный path;
   - installed config не содержит Telegram token;
   - generated unit содержит нужные consumer groups/secret source;
   - staging не меняет production state;
   - reload mechanism авторизован или явно отключен.

Работа не считается завершенной, пока типовой сценарий из README с `./cloudflare.env`, `group: www-data` и managed systemd не проходит end-to-end без production ACME-запроса.
